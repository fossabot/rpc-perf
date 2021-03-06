# rpc-perf - RPC Performance Testing
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fbrayniac%2Frpc-perf.svg?type=shield)](https://app.fossa.io/projects/git%2Bgithub.com%2Fbrayniac%2Frpc-perf?ref=badge_shield)


rpc-perf was created to help measure the performance of caching systems. We've found this tool to be
useful for validating performance of cache backends, effects of kernel version and system tuning, as
well as testing new hardware platforms and network changes.

**BEWARE** rpc-perf can write to its target and can generate many requests
* *run only* if data in the server can be lost/destroyed/corrupted/etc
* *run only* if you understand the impact of sending high-levels of traffic across your network

**Contents**
* [Getting rpc-perf](#getting-rpc-perf)
* [Configuration](#configuration)
* [Sample Usage](#sample-usage)
* [Sample Output](#sample-output)
* [Practices](#practices)
* [Features](#features)
* [Future Work](#future-work)
* [Contributing](#contributing)

## Getting rpc-perf

rpc-perf is built through the `cargo` command which ships with rust. If you don't have Rust
installed, you can use [rustup][rustup] to manage your Rust installation. Otherwise, follow the
instructions on [rust-lang.org](https://rust-lang.org) to get Rust and Cargo installed.
rpc-perf targets stable Rust.

### Build from source

With rust installed, clone this repo, and cd into this folder:

```shell
git clone https://github.com/twitter/rpc-perf.git
cd rpc-perf/rpc-perf
cargo build --release
```

If you need TLS support, you'll need to use nightly Rust:

```shell
git clone https://github.com/twitter/rpc-perf.git
cd rpc-perf/rpc-perf
rustup override set nightly
cargo build --release --features tls
```

This will produce a binary at `../target/release/rpc-perf` which can be run in-place or copied to a
more convenient location on your system.

## Configuration

rpc-perf is configured through a combination of a TOML config file and command line parameters. If 
an option is specified in both the config file and on the command line, the command line wins. See
the `--help` and the example configurations in `rpc-perf/configs` to learn more about configuration.

## Sample Usage

**BEWARE** use caution when running rpc-perf

```shell
# display help
rpc-perf --help

# use a config file and specify an endpoint
rpc-perf --config some_config.toml --endpoint 127.0.0.1:11211

# use a config file and override the request rate
rpc-perf --config some_config.toml --endpoint 127.0.0.1:11211 --request-rate 200000

# use a config file and override the protocol
rpc-perf --config some_config.toml --endpoint 127.0.0.1:6379 --protocol redis

# generate a waterfall plot of request latency
rpc-perf --config some_config.toml --endpoint 127.0.0.1:11211 --interval 60 --windows 5 --waterfall waterfall.png
```

## Practices

* Start with a short test before moving on to tests spanning larger periods of time
* If comparing latency between two setups, be sure to set a ratelimit that's achievable on both
* Keep `--clients` below the number of cores on the machine generating workload
* Increase `--poolsize` as necessary to simulate production-like connection numbers
* You may need to use multiple machines to generate enough workload and/or connections to the target
* Log your configuration and results to make repeating and sharing experiments easy
* Use waterfalls to help visualize latency distribution over time and see anomalies

## Features

* high-resolution latency metrics
* supports memcache and redis protocols
* [mio][mio] for async networking
* optional waterfall visualization of latencies
* powerful workload configuration

## Contributing

* fork on github
* clone your fork
* create a feature branch
* don't forget to run rustfmt
* push your feature branch
* create a pull request

[rustlang]: https://rust-lang.org/
[rustup]: https://rustup.rs
[mio]: https://github.com/carllerche/mio


## License
[![FOSSA Status](https://app.fossa.io/api/projects/git%2Bgithub.com%2Fbrayniac%2Frpc-perf.svg?type=large)](https://app.fossa.io/projects/git%2Bgithub.com%2Fbrayniac%2Frpc-perf?ref=badge_large)