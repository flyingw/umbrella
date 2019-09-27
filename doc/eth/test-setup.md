# setup

Install ethereum
```
$ brew install ethereum
```

# prepare node

Following procedure can be done automatically with `eth_node_init.sh` script.
You can also use `eth_node_start.sh` to start private network node configured previously.

Create two accounts. First one:
```
$ geth --datadir accounts/ account new
Password: test
Repeat password: test

Your new key was generated

Public address of the key:   0x3Ae3F64B827E51b1A49c57a5CAfF88f60AC68816
Path of the secret key file: accounts/keystore/UTC--2019-09-09T14-51-24.097691000Z--3ae3f64b827e51b1a49c57a5caff88f60ac68816
```
And second one:
```
$ geth --datadir accounts/ account new
Password: test
Repeat password: test

Your new key was generated

Public address of the key:   0xDCB73f4C6A71023434748B0086C65262949A8819
Path of the secret key file: accounts/keystore/UTC--2019-09-09T14-58-08.613801000Z--dcb73f4c6a71023434748b0086c65262949a8819
```
Setup genesis
```
$ puppeth
Please specify a network name to administer (no spaces, hyphens or capital letters please)
> network1

What would you like to do? (default = stats)
 1. Show network stats
 2. Configure new genesis
 3. Track new remote server
 4. Deploy network components
> 2

What would you like to do? (default = create)
 1. Create new genesis from scratch
 2. Import already existing genesis
> 1

Which consensus engine to use? (default = clique)
 1. Ethash - proof-of-work
 2. Clique - proof-of-authority
> 2

How many seconds should blocks take? (default = 15)
> 15

Which accounts are allowed to seal? (mandatory at least one)
> 0x3ae3f64b827e51b1a49c57a5caff88f60ac68816 //pub key of first account
> 0x

Which accounts should be pre-funded? (advisable at least one)
> 0xdcb73f4c6a71023434748b0086c65262949a8819 //pub key of second account
> 0x

Should the precompile-addresses (0x1 .. 0xff) be pre-funded with 1 wei? (advisable yes)
> yes

Specify your chain/network ID if you want an explicit one (default = random)
> 123

What would you like to do? (default = stats)
 1. Show network stats
 2. Manage existing genesis
 3. Track new remote server
 4. Deploy network components
> 2

Which folder to save the genesis specs into? (default = current)
  Will create network1.json, network1-aleth.json, network1-harmony.json, network1-parity.json
> 
INFO [09-09|18:01:46.902] Saved native genesis chain spec          path=network1.json

^C
```
Init ethereum node:
```
$ geth --datadir network1/ init network1.json
INFO [09-09|21:01:55.814] Successfully wrote genesis state
```
Copy private keys from accounts to node data directory
```
$ cp accounts/keystore/* network1/keystore/
```
Start node
```
geth --datadir network1/ -verbosity 7 --port 30301 --networkid NETWORK_ID --unlock PUB_KEY --mine console --nodiscover
```
where 
 - NETWORK_ID - network id from genesis. In this readme it's `123`
 - PUB_KEY - wen need to unlock account for mining. account pub key from genesis on question `"Which accounts are allowed to seal?". In this readme it's `0x3ae3f64b827e51b1a49c57a5caff88f60ac68816`
 
 So for out setup we have:
```
geth --datadir network1/ -verbosity 3 --port 30301 --networkid 123 --unlock 0x3ae3f64b827e51b1a49c57a5caff88f60ac68816 --mine console --nodiscover
```

# Eth console 
## Node address
```
> admin.nodeInfo.enode
"enode://16cabdd5c1049a54255a52ed775ee5ed1b4f3fd52bf25b751470a59bda8f093df563dc5d385103e46314ff5dacb8f37fcd988b20efc63b9b5fa78f5417971b48@127.0.0.1:30301?discport"
```
## All accounts
```
> eth.accounts
["0x3ae3f64b827e51b1a49c57a5caff88f60ac68816", "0xdcb73f4c6a71023434748b0086c65262949a8819"]
```
## Send transaction
We have two accounts. Lets send money from genesis prefunded account specifiend on question `"Which accounts should be pre-funded?"`. In this readme it is `0xdcb73f4c6a71023434748b0086c65262949a8819` with password `test`
```
> personal.unlockAccount("0xdcb73f4c6a71023434748b0086c65262949a8819", "test")
true
> eth.sendTransaction({from: "0xdcb73f4c6a71023434748b0086c65262949a8819", to: "0x3ae3f64b827e51b1a49c57a5caff88f60ac68816", value: web3.toWei(1, "ether")})
"0xae76939b961c4c2fc86a741a54c1058af724110e78fac1d1f308670a90344e93"
```
## Pending transactions
```
> eth.pendingTransactions
[{from: "0xdcb73f4c6a71023434748b0086c65262949a8819" ... }]
```
## Balance
```
> web3.fromWei(eth.getBalance("0x3ae3f64b827e51b1a49c57a5caff88f60ac68816"), "ether")
1.000000
```

# run 

Generation of secret key takes a lot of time here. So if you know it in advance better provide it as a `--secret`.

If secret key is unknown, it can be generated from your account keystore json part.
Provide the part of json as `--crypto` parameter.

CRYPTO='{"cipher":"aes-128-ctr","ciphertext":"04a8f7c0411314c926759616119500707f21aae5f4ac71b341a37135c5044453","cipherparams":{"iv":"68b391db784cfa9e2412e3d1f7807e0b"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"f38ac654eb38da995f6a5b2c126998c06463f60a8a08891a0d95ca8d76e383a5"},"mac":"4ebf70584fdea32ea09a2cb565452ea6171baacc4c2fe335ac1193aee85543b1"}'

SECRET="58d3511dfc26b4ac5d96ee66a255d0116afef7a00d9a98973b8e24592857300b"

Run with Ethereum specific parameters.
```
umbrella -vvvv eth \
  --pub_key $NODE_KEY \
  --crypto $CRYPTO \
  --secret $SECRET \
  --password $PASS \
  --out_address $OUT_ADDRESS \
  --dust_address "" \
  --dust_amount "0.0" \
  --data ""
```
