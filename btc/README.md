# btc blockchain client

## prepare
```
brew install bitcoin
bitcoind -regtest -debug=1
```

## build
```
cargo build
```

## run
```
./target/debug/ubtc
cargo run
```

## release
```
cargo build --release
```

## bitcoin-cli
```
bitcoin-cli -regtest getnewaddress
bitcoin-cli -regtest dumpprivkey "address" # secret
bitcoin-cli -regtest getaddressinfo "address" # pubkey
bitcoin-cli -regtest listunspent 0
```