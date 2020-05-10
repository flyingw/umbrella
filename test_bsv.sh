#!/bin/bash

IN_ADD="bsvreg:mqFeyyMpBAEHiiHC4RmDHGg9EdsmZFcjPj" # public key
SECRET="cRVFvtZENLvnV4VAspNkZxjpKvt65KC5pKnKtK7Riaqv5p1ppbnh" # private key
AMOUNT="50.00000000" # unspent amount
CHANGE="0" # do not need
DUST="0" # do not need
OUT_HSH="4bc41432979746dbd6c613dc5b2a2c1234ecc6a5bf3b48d108b4ecba90ea43fe" # unpent txid
OUT_PNT=0 # unpent voud
OUT_ADD="bsvreg:mqFeyyMpBAEHiiHC4RmDHGg9EdsmZFcjPj" # do not need
DST_ADD="bsvreg:mqFeyyMpBAEHiiHC4RmDHGg9EdsmZFcjPj" # do not need
DATA="68656c6c6f2c7361696c6f72" # your message
NETWORK="bsv-reg"

RUST_BACKTRACE=1 cargo run -- $NETWORK \
    --in_address $IN_ADD --in_amount $AMOUNT --secret $SECRET \
    --outpoint_hash $OUT_HSH --outpoint_index $OUT_PNT \
    --out_address $OUT_ADD --change $CHANGE \
    --dust_address $DST_ADD --dust_amount $DUST \
    --data $DATA
