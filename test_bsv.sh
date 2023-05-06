#!/bin/bash

SECRET="cRVFvtZENLvnV4VAspNkZxjpKvt65KC5pKnKtK7Riaqv5p1ppbnh" # private key
AMOUNT="50.00000000" # unspent amount
OUT_HSH="4bc41432979746dbd6c613dc5b2a2c1234ecc6a5bf3b48d108b4ecba90ea43fe" # unpent txid
OUT_PNT=0 # unpent voud
DATA="68656c6c6f2c7361696c6f72" # your message
NETWORK="bsv-reg"

RUST_BACKTRACE=1 cargo run -- $NETWORK \
  --in_address "" \
  --in_amount $AMOUNT \
  --secret $SECRET \
  --outpoint_hash $OUT_HSH \
  --outpoint_index $OUT_PNT \
  --out_address "" \
  --change "0" \
  --dust_address "0" \
  --dust_amount "0" \
  --data $DATA
