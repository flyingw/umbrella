brew install bitcoin

# https://bitcoin.org/en/developer-examples#simple-raw-transaction

bitcoind -regtest -daemon

bitcoin-cli -regtest getnewaddress
> 2NCdoNBtccfNNabxcrqNdVtzCbWJKpQRfQT
export ADDRESS=2NCdoNBtccfNNabxcrqNdVtzCbWJKpQRfQT

# https://bitcoincore.org/en/doc/0.18.0/rpc/generating/generatetoaddress/
bitcoin-cli -regtest generatetoaddress 1 "2NCdoNBtccfNNabxcrqNdVtzCbWJKpQRfQT"
> [
>   "002ae305850e25a7a788eb553f794c44f0c7ba1ecd09a5f31d69da79d52389f8"
> ]
bitcoin-cli -regtest getbalance
> 0.00000000
bitcoin-cli -regtest generatetoaddress 100 "2NCdoNBtccfNNabxcrqNdVtzCbWJKpQRfQT"
> [ ... ]

bitcoin-cli -regtest getbalance
> 50.00000000

# Make transaction
bitcoin-cli -regtest getnewaddress
> 2MwrYuw2aTpygJNJPUPCKYrNaC4A1BkSs8Y
export NEW_ADDRESS=2MwrYuw2aTpygJNJPUPCKYrNaC4A1BkSs8Y
# https://bitcoincore.org/en/doc/0.18.0/rpc/wallet/sendtoaddress/
bitcoin-cli -regtest sendtoaddress $NEW_ADDRESS 10.00
# https://bitcoincore.org/en/doc/0.18.0/rpc/wallet/listunspent/
bitcoin-cli -regtest listunspent
bitcoin-cli -regtest listunspent 0
bitcoin-cli -regtest generatetoaddress 1 $ADDRESS
# https://bitcoincore.org/en/doc/0.18.0/rpc/wallet/getreceivedbyaddress/
bitcoin-cli -regtest getreceivedbyaddress $NEW_ADDRESS 1
> 10.00000000
bitcoin-cli -regtest sendtoaddress $ADDRESS 40.00
bitcoin-cli -regtest generatetoaddress 1 $ADDRESS
bitcoin-cli -regtest getreceivedbyaddress $ADDRESS 1

bitcoin-cli -regtest signrawtransactionwithwallet $RAW_TX
bitcoin-cli -regtest sendrawtransaction $SIGNED_RAW_TX


lsof -iTCP -sTCP:LISTEN -n -P
18443
18444

bitcoind -regtest -rpcport=
bitcoind -regtest -port=18444 -debug=1 -bind=127.0.0.1