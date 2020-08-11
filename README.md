# Umbrella

Universal cross network client to write data into blockchain.

WARN: Do not use with real networks. Test/Private only.

## build

```
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ rustup update
$ cargo build [--release]
$ ./test
```

## downloads

Released binaries

* [v0.1.0](https://github.com/flyingw/umbrella/releases/tag/v0.1.0) Does nothing. Made for internal purposes.
* [v0.2.0](https://github.com/flyingw/umbrella/releases/tag/v0.2.0) Do ETH and BCH transactions.

## local test setup

Select corresponend platform to test:

* [Bitchoin ABS](doc/bch/test-setup.md) and [run](./test.sh)
* [Ethereum](doc/eth/test-setup.md)     and [run](./testht.sh)
* [Bitcoin SV](doc/bsv/test-setup.md)   and [run](./test_bsv.sh)

# links

Definitelly use [rust-bch](https://github.com/brentongunning/rust-bch) library to build Bitcoin Cash application.

Its hard to recommend [parity-ethereum](https://github.com/paritytech/parity-ethereum) project to create Ethereum applications.
We've had a hard times with it and did impossible to get rid of it.

Nice lib bitsv for python. It works with API but was highly inspired by.

## browse

[abe](https://github.com/marioschlipf/bitcoin-abe)

## implementation

limitations:
- use lightweight node
- do not use json apis
- do not use rpc api
- single cli for all blockchains
- native cli = rust

There are differecnt options to implement client which writes data
One way is to use API calls which is relies on thrid paty providers
Other way is to use node. It can be ran as full or lightweight but in either
case user should setup. Local node could allow RPC which is full protocol for cli.
To make client without dependeny to local node we can connect to real nodes.
But as security measure RPC is closed on real nodes. That's why we pretend to be another
node in network. As soon as we send transaction we closing the connection
one of the main downsides of selected solution is no easy way to list unspent.
that is why it is responsibilty of user to provide output with enough funds.
About Rust. When selecting language it was not only choice about efficiently
but about building native client without dependency on vm. it is natural choice
for anyone developing client software. cpp has no benefits here because all
needed librariews are implemented in rust and nothing from system utils is required.
Also it is very nice to binary to be as small as possible that is why this solution
contains minimum of dependencies and we are working to make them bare minimum.
Other optiomizations from compiler also applied to make binary light.
Client is pilyglot. It is supports at the moment bch and eth. In progress btc and bsv.
Support of nem is investigated. Other blockchains' support is subject to discuss.
Other reason to use rust because it is only general-purpose language which 
implements automatic memory managment without garbage collection. Of course it 
has other nice features, for example, concurrency, but we do not use them in this
project.