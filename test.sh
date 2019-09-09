#!/bin/bash

# units BCH, bash needs satoshis
#IN_ADD  = bitcoinabc-cli -regtest getaccountaddress ""
#SECRET  = bitcoinabc-cli -regtest dumpprivkey $IN_ADD
#BALANCE = bitcoinabc-cli -regtest getbalance "" 0 true # getreceivedbyaddress $IN_ADD
#CHANGE  = 
#DUST    = 0.0001
# AMOUNT = bitcoinabc-cli -regtest listtransactions "" 1 0 true - json [ ] + grep "amount"
# OUT_HASH = bitcoinabc-cli -regtest listtransactions "" 1 0 true - json [ ] + grep "txid"
# OUT_IND = bitcoinabc-cli -regtest listtransactions "" 1 0 true - json [ ] + grep "vout"
#OUT_HSH = ""
#OUT_PNT = 0
#OUT_ADD = bitcoinabc-cli -regtest getnewaddress
#DST_ADD = bitcoinabc-cli -regtest getnewaddress
#DATA    = "68686c6c6f2c7361696c6f72"
#NETWORK = "regtest"

IN_ADD="bchreg:qzst858z3jfld7k68tzfzktgk9xje94uaqhe9p2vmn"
SECRET="cQNcVkB3QqJrwkJuEwowxAK9udLgfGyezdG8vNXN3vbRpWEvShtU"
BALANCE="20.00"
CHANGE="19.9998"
DUST="0.0001"
OUT_HSH="ff8c7c3c77aa2e43932ad497cf0c8ba5a24f542ec1bcb7afe329a7166ae8dccd"
OUT_PNT=0
OUT_ADD="bchreg:qpfh27rjv367hst75sq8fghwz3hpn5ygpu9as55x0h"
DST_ADD="bchreg:qzjh3l4drhzq2cy6a0xaped7xwtsxuk9usfzhthe5h"
DATA="68686c6c6f2c7361696c6f72"
NETWORK="bch-reg"

RUST_BACKTRACE=1 cargo run -- $NETWORK \
    --in_address $IN_ADD --in_amount $BALANCE --secret $SECRET \
    --outpoint_hash $OUT_HSH --outpoint_index $OUT_PNT \
    --out_address $OUT_ADD --change $CHANGE \
    --dust_address $DST_ADD --dust_amount $DUST \
    --data $DATA

# in regtest mode you can't receive any network message yet except errors
# so just put transaction in block to terinate:
#
# > bitcoin-cli -regtest getnewaddress
# $ [ "bchreg:a"]
# > bitcoin-cli -regtest generatetoaddress 1 bchreg:a
#
# check unspent:
#
# >bitcoinabc-cli -regtest listunspent
#
