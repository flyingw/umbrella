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

## browse

[abe](git@github.com:marioschlipf/bitcoin-abe.git)
