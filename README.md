# Umbrella

Universal cross network client to write data into blockchain.

WARN: Do not use with real networks. Regtest only.

# download

[v0.1.0] (http://didactic.umbrella/)

# prerequisites

```
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ rustup update
```

# build 

```
$ cargo build
```

# test

Setup Bitcoin Node and CLI tools

```
$ brew install bitcoin
$ git clone https://github.com/Bitcoin-ABC/bitcoin-abc.git | make
$ etc.

```

# run 

Run bitcoin node in regtest mode to test connection localy.

```
$ bitcoind[core|abc] -regtest
$ cargo run -- -vvvv [optional parameters: -v, -network, etc.] [--help: for details]
```

# links

Use [rust-bch](https://github.com/brentongunning/rust-bch) library to build Bitcoin Cash application.

