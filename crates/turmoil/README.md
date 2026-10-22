# turmoil

The full-stack entry point for the turmoil family. Bundles a runtime, a
simulated network, and a simulated filesystem behind a single `Builder` — start
here if you want a complete simulation harness. Reach for `turmoil-net` or
`turmoil-fs` directly if you're assembling your own runtime.

The network runs on [`turmoil-net`](../turmoil-net) — a TCP/UDP stack per
host — and the filesystem on [`turmoil-fs`](../turmoil-fs). turmoil owns the
runtime, the topology (latency, partitions, holds), and crashes.

```toml
[dev-dependencies]
turmoil = "0.7"
```

## Barriers (unstable)

*Requires the `unstable-barriers` feature.*

Barriers let tests observe and control specific points in the code under
test. A `trigger(event)` call in production code (conditionally compiled)
blocks until the test resolves it, giving you deterministic scheduling of
arbitrary events without threading them through the network. See the
`barriers` module for details.
