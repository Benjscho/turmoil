//! Deterministic network simulation for turmoil.
//!
//! `turmoil-net` is a simulated socket stack. Production code imports
//! [`tokio::net`]; tests swap the import for [`shim::tokio::net`] and
//! run the same code against a fully deterministic network.
//!
//! The crate README has the motivation and code examples. The module
//! list below is a map of the code:
//!
//! - [`shim`] — drop-in replacements for `tokio::net` types.
//!   Production code changes one import and runs unchanged.
//! - [`fixture`] — batteries-included scheduler + runtime for the
//!   common shapes ([`fixture::lo`] single-host, [`fixture::ClientServer`]
//!   multi-host). Start here; drop to the primitives when you outgrow
//!   them.
//! - [`Net`] / [`EnterGuard`] — the primitives the fixtures are built
//!   on. Build a topology with [`Net::add_host`], install it with
//!   [`Net::enter`], drive the fabric with [`EnterGuard::egress_all`] /
//!   [`EnterGuard::evaluate`] / [`EnterGuard::deliver`].
//! - [`Rule`] / [`Verdict`] / [`rule`] — packet-level fault injection.
//!   Rules see every non-loopback packet and decide Pass / Deliver
//!   (with optional delay) / Drop.
//! - [`netstat`] — Linux-style socket snapshot for debugging a test.
//!
//! [`tokio::net`]: https://docs.rs/tokio/latest/tokio/net/index.html

use std::cell::RefCell;

use indexmap::IndexMap;

mod dns;
mod fabric;
pub mod fixture;
mod kernel;
mod netstat;
mod rule;
pub mod shim;

use crate::dns::Dns;
pub use crate::dns::{ToIpAddr, ToIpAddrs};
use crate::fabric::Fabric;
pub use crate::fabric::HostId;
use crate::kernel::Kernel;
pub use crate::kernel::{
    Interface, InterfaceId, KernelConfig, Packet, TcpFlags, TcpSegment, Transport, UdpDatagram,
};
pub use crate::netstat::{Netstat, NetstatEntry, NetstatState, Proto};
pub use crate::rule::{Latency, Rule, RuleGuard, RuleId, Verdict};

thread_local! {
    static CURRENT: RefCell<Option<Net>> = const { RefCell::new(None) };
}

type Resolver = Box<dyn Fn(&str) -> Option<std::net::IpAddr>>;

pub struct Net {
    fabric: Fabric,
    dns: Dns,
    /// Harness-supplied name lookup, consulted before `dns`.
    resolver: Option<Resolver>,
    current: Option<HostId>,
    /// Installed rules, consulted in insertion order.
    rules: IndexMap<RuleId, Box<dyn Rule>>,
    next_rule_id: u64,
}

impl Net {
    pub fn new() -> Self {
        Self::with_config(KernelConfig::default())
    }

    /// `cfg` is applied to every host added later.
    pub fn with_config(cfg: KernelConfig) -> Self {
        Self {
            fabric: Fabric::new(cfg),
            dns: Dns::new(),
            resolver: None,
            current: None,
            rules: IndexMap::new(),
            next_rule_id: 1,
        }
    }

    /// Register a host. `addrs` accepts hostnames (auto-allocated to
    /// 192.168.x.x on first sight, idempotent on reuse) or literal
    /// IPs. Loopback (127.0.0.1, ::1) is implicit — do not pass it.
    /// Panics if an address is already claimed by another host, or
    /// if loopback is passed explicitly. The first host added becomes
    /// current.
    pub fn add_host<A: ToIpAddrs>(&mut self, addrs: A) -> HostId {
        let ips = addrs.to_ip_addrs(&mut self.dns);
        let id = self.fabric.add_host(ips);
        if self.current.is_none() {
            self.current = Some(id);
        }
        id
    }

    /// Inspect a host's loopback and shared-link interfaces.
    pub fn interfaces(&self, host: HostId) -> &[Interface] {
        self.fabric.kernel(host).interfaces()
    }

    /// Resolve `name` to its registered IP, allocating if unseen.
    /// Mirrors the name resolution used by [`Net::add_host`] and the
    /// shim's hostname-aware socket addrs.
    pub fn lookup(&mut self, name: &str) -> std::net::IpAddr {
        self.dns.resolve(name)
    }

    pub fn host_ids(&self) -> impl Iterator<Item = HostId> + '_ {
        self.fabric.host_ids()
    }

    /// The host owning `ip`. `None` for loopback and unclaimed IPs.
    pub fn host_for_ip(&self, ip: std::net::IpAddr) -> Option<HostId> {
        self.fabric.host_for_ip(ip)
    }

    /// Resolve hostnames through `resolver` before the built-in DNS.
    /// For harnesses that own the name → IP mapping (and register
    /// hosts by literal IP).
    pub fn set_resolver(&mut self, resolver: impl Fn(&str) -> Option<std::net::IpAddr> + 'static) {
        self.resolver = Some(Box::new(resolver));
    }

    /// Drain one host's outbound packets into `out`. For harnesses
    /// that step hosts individually — [`EnterGuard::egress_all`] is
    /// the all-hosts form.
    pub fn egress(&mut self, host: HostId, out: &mut Vec<Packet>) {
        self.fabric.egress(host, out);
    }

    /// Hosts that should receive `pkt`: the owner of a unicast
    /// destination, or every other host on the shared link for UDP
    /// broadcast/multicast. Empty for unknown destinations. Lets a
    /// harness apply per-link faults to each copy of a cast.
    pub fn receivers(&self, pkt: &Packet) -> Vec<HostId> {
        self.fabric.receivers(pkt)
    }

    /// Hand `pkt` to `host`'s stack, bypassing routing. Pair with
    /// [`Net::receivers`].
    pub fn deliver_to(&mut self, host: HostId, pkt: Packet) {
        self.fabric.deliver_to(host, pkt);
    }

    /// Walk the installed rules for `pkt`. First non-`Pass` verdict
    /// wins; an empty rule chain returns `Verdict::Pass`.
    pub fn evaluate(&mut self, pkt: &Packet) -> Verdict {
        for rule in self.rules.values_mut() {
            match rule.on_packet(pkt) {
                Verdict::Pass => continue,
                v => return v,
            }
        }
        Verdict::Pass
    }

    /// Crash `host`'s stack: every socket and queued packet vanishes
    /// without a FIN or RST. Peers find out when they next hear from
    /// the host, or when their retransmits give up.
    pub fn reset_host(&mut self, host: HostId) {
        self.fabric.kernel_mut(host).reset();
    }

    /// Snapshot `host`'s socket table. The free [`netstat`] function
    /// is the form for code running inside the installed `Net`.
    pub fn netstat(&self, host: HostId) -> Netstat {
        netstat::snapshot(self.fabric.kernel(host))
    }

    /// Install a rule for the life of the `Net`. Use this when the
    /// rule is part of the test's fixed setup (symmetric latency,
    /// permanent packet filter, etc). For rules that only apply to
    /// a phase of the test, use the guard-returning [`rule`] free
    /// function from inside the sim instead.
    pub fn rule(&mut self, rule: impl Rule) {
        self.install_rule(Box::new(rule));
    }

    fn install_rule(&mut self, rule: Box<dyn Rule>) -> RuleId {
        let id = RuleId(self.next_rule_id);
        self.next_rule_id += 1;
        self.rules.insert(id, rule);
        id
    }

    fn uninstall_rule(&mut self, id: RuleId) {
        self.rules.shift_remove(&id);
    }

    fn lookup_name(&self, name: &str) -> Option<std::net::IpAddr> {
        self.resolver
            .as_ref()
            .and_then(|resolve| resolve(name))
            .or_else(|| self.dns.lookup(name))
    }

    /// Panics if another `Net` is already installed on this thread.
    pub fn enter(self) -> EnterGuard {
        CURRENT.with(|c| {
            let mut slot = c.borrow_mut();
            assert!(slot.is_none(), "another Net is already installed");
            *slot = Some(self);
        });
        EnterGuard { _priv: () }
    }
}

impl std::fmt::Debug for Net {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Net")
            .field("fabric", &self.fabric)
            .field("dns", &self.dns)
            .field("resolver", &self.resolver.is_some())
            .field("current", &self.current)
            .field("rules", &format!("{} installed", self.rules.len()))
            .finish()
    }
}

impl Default for Net {
    fn default() -> Self {
        Self::new()
    }
}

#[must_use = "a Net is only active while the guard is held"]
pub struct EnterGuard {
    _priv: (),
}

impl EnterGuard {
    /// Uninstall the `Net` and hand it back. Harnesses that interleave
    /// several simulations on one thread install a `Net` only while
    /// running its hosts, then park it until the next step.
    pub fn exit(self) -> Net {
        let net = CURRENT.with(|c| c.borrow_mut().take().expect("guard is live"));
        std::mem::forget(self);
        net
    }

    /// Drain every host's outbound queue into `out`. The caller decides
    /// what happens next — typically: consult rules via
    /// [`EnterGuard::evaluate`] for each packet and then
    /// [`EnterGuard::deliver`] (or schedule for later). The buffer is
    /// passed in so the caller can reuse its allocation across ticks.
    /// See [`fixture`] for the default tokio-driven loop.
    pub fn egress_all(&self, out: &mut Vec<Packet>) {
        CURRENT.with(|c| {
            c.borrow_mut()
                .as_mut()
                .expect("guard is live")
                .fabric
                .egress_all(out)
        });
    }

    /// Route unicast to the host owning its destination IP, or fan out
    /// UDP broadcast/multicast to other hosts on the shared link.
    /// Unknown unicast destinations are silently dropped.
    pub fn deliver(&self, pkt: Packet) {
        CURRENT.with(|c| {
            c.borrow_mut()
                .as_mut()
                .expect("guard is live")
                .fabric
                .deliver(pkt)
        });
    }

    /// Walk installed rules for `pkt`. First non-`Pass` verdict wins;
    /// empty rule chain returns `Verdict::Pass`.
    pub fn evaluate(&self, pkt: &Packet) -> Verdict {
        CURRENT.with(|c| {
            c.borrow_mut()
                .as_mut()
                .expect("guard is live")
                .evaluate(pkt)
        })
    }

    /// Pin which host subsequent `sys()` calls (i.e. socket syscalls
    /// from any task spawned inside this guard) talk to.
    pub fn set_current(&self, id: HostId) {
        CURRENT.with(|c| {
            c.borrow_mut().as_mut().expect("guard is live").current = Some(id);
        });
    }

    /// Install a rule, vending a [`RuleGuard`] that uninstalls it on
    /// drop. Useful in schedulers or fixture code that owns the
    /// guard's lifetime explicitly — async tasks should call the
    /// free [`rule`] function instead.
    pub fn rule(&self, r: impl Rule) -> RuleGuard {
        RuleGuard::new(install_rule(Box::new(r)))
    }
}

impl Drop for EnterGuard {
    fn drop(&mut self) {
        CURRENT.with(|c| *c.borrow_mut() = None);
    }
}

/// Like [`sys`], but a no-op when no `Net` or current host is
/// installed. For `Drop` impls: sockets may outlive their simulation
/// during teardown, and there is nothing left to close.
pub(crate) fn sys_if_installed(f: impl FnOnce(&mut Kernel)) {
    CURRENT.with(|c| {
        let mut cell = c.borrow_mut();
        let Some(net) = cell.as_mut() else { return };
        let Some(id) = net.current else { return };
        if let Some(kernel) = net.fabric.try_kernel_mut(id) {
            f(kernel);
        }
    })
}

pub(crate) fn sys<R>(f: impl FnOnce(&mut Kernel) -> R) -> R {
    CURRENT.with(|c| {
        let mut cell = c.borrow_mut();
        let net = cell
            .as_mut()
            .expect("no Net installed — call Net::enter() first");
        let id = net
            .current
            .expect("no current host — register one with Net::add_host()");
        f(net.fabric.kernel_mut(id))
    })
}

/// Resolve `name` against the installed `Net`'s DNS. Returns `None`
/// if there is no `Net` installed, or if the name isn't registered
/// and can't be parsed as an IP literal.
pub fn lookup_host(name: &str) -> Option<std::net::IpAddr> {
    CURRENT.with(|c| c.borrow().as_ref().and_then(|net| net.lookup_name(name)))
}

/// Pin which host subsequent [`sys`](crate) calls (i.e. socket
/// syscalls from the caller's task) talk to.
///
/// This is the free-function form of [`EnterGuard::set_current`], for
/// use where the guard isn't in scope — typically inside a future
/// wrapper that rescopes every poll. Harnesses with shared-runtime
/// fixtures (see [`fixture::ClientServer`] for the canonical pattern)
/// call this on entry to each task's poll so `sys()` lookups land in
/// the right kernel.
///
/// Panics if no `Net` is installed.
pub fn set_current(id: HostId) {
    CURRENT.with(|c| {
        c.borrow_mut()
            .as_mut()
            .expect("no Net installed — call Net::enter() first")
            .current = Some(id);
    });
}

/// Install a rule and return a guard that uninstalls it on drop.
/// Callable from any task inside an installed `Net`. Panics if no
/// `Net` is installed.
///
/// For rules that should live for the entire simulation, use
/// [`Net::rule`] before calling [`Net::enter`].
pub fn rule(r: impl Rule) -> RuleGuard {
    RuleGuard::new(install_rule(Box::new(r)))
}

fn install_rule(r: Box<dyn Rule>) -> RuleId {
    CURRENT.with(|c| {
        c.borrow_mut()
            .as_mut()
            .expect("no Net installed — call Net::enter() first")
            .install_rule(r)
    })
}

fn uninstall_rule(id: RuleId) {
    CURRENT.with(|c| {
        // Tolerant of the Net already being gone — drop order during
        // teardown isn't guaranteed.
        if let Some(net) = c.borrow_mut().as_mut() {
            net.uninstall_rule(id);
        }
    });
}

/// Snapshot a host's socket table, Linux `netstat`-style. `host`
/// accepts a hostname (resolved via DNS like [`Net::add_host`]) or a
/// literal IP. Panics if no `Net` is installed, or if the address
/// doesn't match a registered host. Loopback isn't routable on its
/// own — pass a hostname or the host's configured IP.
pub fn netstat<H: ToIpAddr>(host: H) -> Netstat {
    CURRENT.with(|c| {
        let cell = c.borrow();
        let net = cell
            .as_ref()
            .expect("no Net installed — call Net::enter() first");
        let ip = host
            .try_to_ip_addr(&net.dns)
            .expect("hostname not registered");
        let id = net
            .fabric
            .host_for_ip(ip)
            .unwrap_or_else(|| panic!("no host registered for {ip}"));
        netstat::snapshot(net.fabric.kernel(id))
    })
}
