# umbrella

Universal cross network client to write data into blockchain.

| network | tx   | regtest | mainnet  |
|:-------:|:----:|:-------:|:--------:|
| BCH     | done |         |          |
| BSV     | done | tested  | api only |
| ETH     | done | tested  |          |
| NEM     |      |         |          |

## build

```sh
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
cargo build [--release]
./test
```

## downloads

Released binaries

* [v0.1.0](https://github.com/flyingw/umbrella/releases/tag/v0.1.0) Does nothing. Made for internal purposes.
* [v0.2.0](https://github.com/flyingw/umbrella/releases/tag/v0.2.0) Do ETH and BCH transactions.
* [v0.3.0](https://github.com/flyingw/umbrella/releases/tag/v0.3.0) Do BSV transaction.

## local test setup

Select corresponend platform to test:

* [Bitchoin ABS](doc/bch/test-setup.md) and [run](./test_bch.sh)
* [Ethereum](doc/eth/test-setup.md)     and [run](./test_eth.sh)
* [Bitcoin SV](doc/bsv/test-setup.md)   and [run](./test_bsv.sh)

# links

Definitelly use [rust-bch](https://github.com/brentongunning/rust-bch) library to build Bitcoin Cash application.

Its hard to recommend [parity-ethereum](https://github.com/paritytech/parity-ethereum) project to create Ethereum applications.
We've had a hard times with it and did impossible to get rid of it.

## browse

[abe](https://github.com/marioschlipf/bitcoin-abe)
