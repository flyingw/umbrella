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

- fee is 0.002

bitcoin-cli -regtest getnewaddress
> 2MviY9i8P8FLB2Cnknb4qwA1cayZPzKEwQK

bitcoin-cli -regtest generatetoaddress 11 2MviY9i8P8FLB2Cnknb4qwA1cayZPzKEwQK

bitcoin-cli -regtest getbalance
> 50.0

bitcoin-cli -regtest getnewaddress
> 2N1uuR59i3GrXDdBAiAcTZNzcXsiwDYdJ9w

bitcoin-cli -regtest sendtoaddress 2N1uuR59i3GrXDdBAiAcTZNzcXsiwDYdJ9w 10
> 84173d81e4d134d3595f0806df1cb6598754202c36d7ae19607aecddfe7abd12

bitcoin-cli -regtest dumpprivkey "2MviY9i8P8FLB2Cnknb4qwA1cayZPzKEwQK"
> cRp26HzBrkpH5J98PisgFH4de2tgFYmPDLXL8DuyiGBURmC3PkA1

bitcoin-cli -regtest validateaddress 2N1uuR59i3GrXDdBAiAcTZNzcXsiwDYdJ9w
> a9145f11b9a2f93cba30a47d154e91294c89996b721e87
bitcoin-cli -regtest validateaddress 2MviY9i8P8FLB2Cnknb4qwA1cayZPzKEwQK
> a9142612c50622bb4aba8dacd64e5766e35634e4b33187

- sending back 10 from 2N to 2M


brew cask install docker
open Docker.app
docker run -d --rm --name bitcoind -v "$PWD/data:/data" bitcoinsv/bitcoin-sv bitcoind -regtest -debug=1
docker run --rm --network container:bitcoind bitcoinsv/bitcoin-sv bitcoin-cli -regtest <cmd>
docker run --rm --network container:bitcoind bitcoinsv/bitcoin-sv bitcoin-cli -regtest getnewaddress
public key mqFeyyMpBAEHiiHC4RmDHGg9EdsmZFcjPj
docker run --rm --network container:bitcoind bitcoinsv/bitcoin-sv bitcoin-cli -regtest generatetoaddress 200 mqFeyyMpBAEHiiHC4RmDHGg9EdsmZFcjPj
docker run --rm --network container:bitcoind bitcoinsv/bitcoin-sv bitcoin-cli -regtest getbalance
docker run --rm --network container:bitcoind bitcoinsv/bitcoin-sv bitcoin-cli -regtest dumpprivkey "mqFeyyMpBAEHiiHC4RmDHGg9EdsmZFcjPj"
private key cRVFvtZENLvnV4VAspNkZxjpKvt65KC5pKnKtK7Riaqv5p1ppbnh
docker run --rm --network container:bitcoind bitcoinsv/bitcoin-sv bitcoin-cli -regtest listunspent 0
  {
    "txid": "4bc41432979746dbd6c613dc5b2a2c1234ecc6a5bf3b48d108b4ecba90ea43fe",
    "vout": 0,
    "address": "mqFeyyMpBAEHiiHC4RmDHGg9EdsmZFcjPj",
    "account": "",
    "scriptPubKey": "76a9146acc9139e75729d2dea892695e54b66ff105ac2888ac",
    "amount": 50.00000000,
    "confirmations": 120,
    "spendable": true,
    "solvable": true,
    "safe": true
  }

open main.py
python3 main.py
> hex
0100000001fe43ea90baecb408d1483bbfa5c6ec34122c2a5bdc13c6d6db4697973214c44b000000006a473044022061a2345fc53668a542adc7a184a9ad9f91c735c90cbb20c913c18bbdc505abc5022023925a703e84050022c79f7c222244785effb41058f2e02339a28e941230538641210347fa53577cf93729ac48b1bc44df12d3dd9b88c2d9991abe84000e94728e9a26ffffffff02000000000000000003006a789af1052a010000001976a9146acc9139e75729d2dea892695e54b66ff105ac2888ac00000000

docker run --rm --network container:bitcoind bitcoinsv/bitcoin-sv bitcoin-cli -regtest sendrawtransaction <hex>
docker run --rm --network container:bitcoind bitcoinsv/bitcoin-sv bitcoin-cli -regtest sendrawtransaction 0100000001fe43ea90baecb408d1483bbfa5c6ec34122c2a5bdc13c6d6db4697973214c44b000000006a473044022061a2345fc53668a542adc7a184a9ad9f91c735c90cbb20c913c18bbdc505abc5022023925a703e84050022c79f7c222244785effb41058f2e02339a28e941230538641210347fa53577cf93729ac48b1bc44df12d3dd9b88c2d9991abe84000e94728e9a26ffffffff02000000000000000003006a789af1052a010000001976a9146acc9139e75729d2dea892695e54b66ff105ac2888ac00000000
> 0afe96427661ae54ea125166bc3127f9ffc2d273f2c815aef8e6cbd9f35d86f0


docker run --rm --network container:bitcoind bitcoinsv/bitcoin-sv bitcoin-cli -regtest decoderawtransaction "0100000001fe43ea90baecb408d1483bbfa5c6ec34122c2a5bdc13c6d6db4697973214c44b000000006a473044022061a2345fc53668a542adc7a184a9ad9f91c735c90cbb20c913c18bbdc505abc5022023925a703e84050022c79f7c222244785effb41058f2e02339a28e941230538641210347fa53577cf93729ac48b1bc44df12d3dd9b88c2d9991abe84000e94728e9a26ffffffff02000000000000000003006a789af1052a010000001976a9146acc9139e75729d2dea892695e54b66ff105ac2888ac00000000"
       "scriptPubKey": {
        "asm": "0 OP_RETURN OP_OVER",
        "hex": "006a78", -- "x"
        "type": "nonstandard"
      }
