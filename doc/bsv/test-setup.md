# setup 

Setup Bitcoin SV and CLI tools

```
vim ~/Library/Application\ Support/Bitcoin/bitcoin.conf
regtest=1
rpcpassword=password
rpcuser=bitcoin

vim ./data/bitcoin.conf
rinttoconsole=1
rpcallowip=::/0
rpcpassword=password
rpcuser=bitcoin
excessiveblocksize=2000000000
maxstackmemoryusageconsensus=200000000
regtest=1
server=1
debug=1
rpcport=18443

brew cask install docker
open Docker.app
docker run -p 18444:18444 -p 18443:18443 -d --rm --name bitcoind -v "$PWD/data:/data" bitcoinsv/bitcoin-sv bitcoind
bitcoin-cli getnewaddress
> mqFeyyMpBAEHiiHC4RmDHGg9EdsmZFcjPj (public key)
bitcoin-cli generatetoaddress 200 mqFeyyMpBAEHiiHC4RmDHGg9EdsmZFcjPj
bitcoin-cli dumpprivkey "mqFeyyMpBAEHiiHC4RmDHGg9EdsmZFcjPj"
> cRVFvtZENLvnV4VAspNkZxjpKvt65KC5pKnKtK7Riaqv5p1ppbnh (private key)
bitcoin-cli listunspent 0
> "txid": "4bc41432979746dbd6c613dc5b2a2c1234ecc6a5bf3b48d108b4ecba90ea43fe",
> "vout": 0,
> "amount": 50.00000000,
> "confirmations": 120,
```

# send data

```
umbrella -vvvv bsv \
  --in_address $IN_ADD \
  --in_amount $BALANCE \
  --secret $SECRET \
  --outpoint_hash $OUT_HSH \
  --outpoint_index $OUT_PNT \
  --out_address $OUT_ADD \
  --change $CHANGE \
  --dust_address $DST_ADD \
  --dust_amount $DUST \
  --data $DATA
```
