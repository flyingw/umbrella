# setup

```sh
docker run -p 18444:18444 -p 18443:18443 -d --rm --name bitcoind -v "$PWD/data:/data" bitcoinsv/bitcoin-sv bitcoind

vim ./data/bitcoin.conf
...
regtest=1
server=1
debug=1
rpcport=18443

docker stop bitcoind
docker run -p 18444:18444 -p 18443:18443 -d --rm --name bitcoind -v "$PWD/data:/data" bitcoinsv/bitcoin-sv bitcoind

brew install bitcoin

touch ~/Library/Application\ Support/Bitcoin/bitcoin.conf
vim ~/Library/Application\ Support/Bitcoin/bitcoin.conf
regtest=1
rpcpassword=password
rpcuser=bitcoin

bitcoin-cli getnewaddress
> mhCJckDWfFvNnK2bswTBxUW49JZvJ9ARaw (public key)

bitcoin-cli generatetoaddress 200 "mhCJckDWfFvNnK2bswTBxUW49JZvJ9ARaw"

bitcoin-cli dumpprivkey "mhCJckDWfFvNnK2bswTBxUW49JZvJ9ARaw"
> cPgZDe7yAqmjDGK7vuvFrh79gjLKqGGBkuGiJrAEtmCKhJiNmCGd (private key)

bitcoin-cli listunspent 0
> "txid": "1409b3059aca971958999e70df51749d14b4280e979165b4f24ff79ddcf58dfe",
> "vout": 0,
> "amount": 25.00000000,
> "confirmations": 165,

export BALANCE="25.00000000"
export SECRET="cPgZDe7yAqmjDGK7vuvFrh79gjLKqGGBkuGiJrAEtmCKhJiNmCGd"
export OUT_HSH="1409b3059aca971958999e70df51749d14b4280e979165b4f24ff79ddcf58dfe"
export OUT_PNT="0"
export DATA="68656c6c6f2c7361696c6f72"
export NETWORK="bsv-reg"

RUST_BACKTRACE=1 cargo run -- $NETWORK \
  --in_address "" \
  --in_amount $BALANCE \
  --secret $SECRET \
  --outpoint_hash $OUT_HSH \
  --outpoint_index $OUT_PNT \
  --out_address "" \
  --change "0" \
  --dust_address "" \
  --dust_amount "0" \
  --data $DATA
> DEBUG - transaction hash: 1ddc1ecad78fa78007d2f80c6698c8f45ec32f4687fae40aee4d39bce3a74fc8

docker logs bitcoind

bitcoin-cli gettransaction 1ddc1ecad78fa78007d2f80c6698c8f45ec32f4687fae40aee4d39bce3a74fc8
> "hex": "..."

bitcoin-cli decoderawtransaction "..."
> {
>   "value": 0.00,
>   "n": 0,
>   "scriptPubKey": {
>     "asm": "0 OP_RETURN 68656c6c6f2c7361696c6f72",
>     "hex": "006a0c68656c6c6f2c7361696c6f72",
>     "type": "nulldata"
>   }
> },

echo 68656c6c6f2c7361696c6f72 | xxd -r -p
> hello,sailor
```

## notes

```sh
docker ps
docker exec -it bitcoind bash
docker run --rm --network container:bitcoind bitcoinsv/bitcoin-sv bitcoin-cli -regtest <cmd>

bitcoin-cli getbalance
bitcoin-cli setban "172.17.0.1" "remove"

./test_bsv.sh
```
