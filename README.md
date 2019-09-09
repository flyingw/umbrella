# Umbrella

Universal cross network client to write data into blockchain.

WARN: Do not use with real networks. Regtest only.

## downloads

[v0.1.0](https://github.com/flyingw/umbrella/releases/tag/v0.1.0)

## build 

```
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ rustup update
$ cargo build
```

```
cargo build
./target/debug/umbrella
cargo run
cargo build --release
```

## test setup

Setup Bitcoin Node and CLI tools

```
$ brew install bitcoin
$ git clone https://github.com/Bitcoin-ABC/bitcoin-abc.git | make
$ etc.
```

## run 

Run bitcoin node in regtest mode to test connection localy.

```
$ bitcoind[core|abc] -regtest
$ umbrella -vvvv --in_address $IN_ADD --in_amount $BALANCE --secret $SECRET
    --outpoint_hash $OUT_HSH --outpoint_index $OUT_PNT
    --out_address $OUT_ADD --change $CHANGE
    --dust_address $DST_ADD --dust_amount $DUST
    --data $DATA --network $NETWORK
[--help: for details]
```

### btc
```bash
bitcoind -regtest -debug=1
cargo run btc-reg --change 0.01 --data "68" --dust_address "" --dust_amount 0.1 --in_address "" --in_amount 1.0 --out_address "" --outpoint_hash "ff8c7c3c77aa2e43932ad497cf0c8ba5a24f542ec1bcb7afe329a7166ae8dccd" --outpoint_index 0 --secret ""
```

# links

Use [rust-bch](https://github.com/brentongunning/rust-bch) library to build Bitcoin Cash application.

## browse

[abe](https://github.com/marioschlipf/bitcoin-abe)
