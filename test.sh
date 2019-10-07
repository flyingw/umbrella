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

IN_ADD="bchreg:qphrcrv0ua00njxu6jd7rs7n7ntepmvvuvglc80jdn"
SECRET="cN4hMbVEjSwQEafm5Morxh59CeTpK6MdE4oaVf52TXMYr6CkQQ4F"
BALANCE="1.0000"
CHANGE="0.9998"
DUST="0.0001"
OUT_HSH="df2741a4164630be86a7528f05da3cdc4acc514569a89017eea4b303a0d66412"
OUT_PNT=0
OUT_ADD="bchreg:qqkwrtcw4hqnnsdpsntey63ll8qlr2phsczpqydl98"
DST_ADD="bchreg:qq6j8yswty4n4unqqcxp2ujuy6eh5769h52dt69vml"
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
