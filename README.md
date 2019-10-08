# Umbrella

Universal cross network client to write data into blockchain.

WARN: Do not use with real networks. Test/Private only.

## build

```
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ rustup update
$ cargo build [--release]
```

## downloads

Released binaries

* [v0.1.0](https://github.com/flyingw/umbrella/releases/tag/v0.1.0) Does nothing. Made for internal purposes.
* [v0.2.0](https://github.com/flyingw/umbrella/releases/tag/v0.2.0) Do ETH and BCH transactions.


## local test setup

Select corresponend platform to test:

* [Bitchoin ABS](doc/bch/test-setup.md)
* [Ethereum](doc/eth/test-setup.md)

# links

Definitelly use [rust-bch](https://github.com/brentongunning/rust-bch) library to build Bitcoin Cash application.

Its hard to recommend [parity-ethereum](https://github.com/paritytech/parity-ethereum) project to create Ethereum applications.
We've had a hard times with it and did impossible to get rid of it.

## browse

[abe](https://github.com/marioschlipf/bitcoin-abe)
