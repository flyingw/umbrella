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
