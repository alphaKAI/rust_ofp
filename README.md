rust_ofp [![Build Status](https://travis-ci.org/baxtersa/rust_ofp.svg?branch=master)](https://travis-ci.org/baxtersa/rust_ofp) [![](http://meritbadge.herokuapp.com/rust_ofp)](https://crates.io/crates/rust_ofp)
===
OpenFlow 1.0 protocol and controller in Rust.
---
`rust_ofp` aims to implement the OpenFlow1.0 protocol, for purposes of prototyping SDN systems in Rust. In the future, this may grow to support other OpenFlow specifications (namely 1.3), and others protocols entirely.

I'm drawing heavily on inspiration and code structure from the [frenetic-lang](https://github.com/frenetic-lang) project, due to my familiarity with it. I hope that Rust will enable a more natural implementation of the low-level protocol than OCaml + CStructs, and true parallelism will allow for higher controller performance and a simpler event loop.

See my blog post on the crate [here](http://baxtersa.github.io/2016/12/30/rust-openflow-0x01.html)!

Building
---
`rust_ofp` is composed of a Rust library implementing the OpenFlow 1.0 protocol, and a `rust_ofp_controller` binary that currently acts as little more than an echo server for SDN configurations. It can be built and run by the normal means for Rust projects.
```bash
cd path/to/rust_ofp
cargo build
cargo run
```

Testing
---
I'm performing all correctness evaluation in [mininet](https://mininet.org) for the time being. Mininet offers quick feedback, as much scalability as I need for now, and should properly support OpenFlow 1.0 (and other protocols). There is no reason correctness in mininet shouldn't transfer to physical hardware as well, and maybe one day I'll get around to testing out that hypothesis.

Anyway, testing the controller binary is pretty straightforward, assuming mininet is installed.
In one terminal
```bash
cd path/to/rust_ofp
cargo run
```
In another terminal
```bash
sudo  mn --controller=remote
```
The terminal running `rust_ofp_controller` will occasionally print some things out, logging a rough idea of the types of messages it receives, and behaviors it performs.

The mininet terminal should launch an interactive shell with the typical mininet utilities. 

Currently, the test executable for `rust_ofp` implements MAC learning, so as hosts ping eachother, the controller installs forwarding rules on switches rather than routing all packets through the controller.

Documentation
---
Travis CI automatically uploads source documentation generated by `cargo doc`.
 - [`rust_ofp`](https://baxtersa.github.io/rust_ofp/docs)
 - [`rust_ofp_controller`](https://baxtersa.github.io/rust_ofp/docs/rust_ofp_controller)

ToDo
---
Some parts of the OpenFlow 1.0 standard remain unimplemented. Notably, `rust_ofp` does not currently implement the following message codes:
 - `OFPT_VENDOR`
 - `OFPT_GET_CONFIG_REQUEST/OFPT_GET_CONFIG_REPLY`
 - `OFPT_SET_CONFIG`
 - `OFPT_PORT_MOD`
 - `OFPT_STATS_REQUEST/OFPT_STATS_REPLY`
 - `OFPT_QUEUE_GET_CONFIG_REQUEST/OFPT_QUEUE_GET_CONFIG_REPLY`

The current controller executable is a minimal wrapper around the protocol that doesn't dynamically handle any rule configuration. Future goals for the controller include:
 - A GTK GUI for configuring and querying an SDN dynamically.
 - A compiler from some higher-level abstraction to install a forwarding policy other than a global `DROP` on launch.
 - [Consistent Updates](http://www.cs.cornell.edu/~jnfoster/papers/frenetic-consistent-updates.pdf) for dynamically updating an SDN's global forwarding policy.
