# setup 

Setup Bitcoin Cash Node and CLI tools

```
$ git clone https://github.com/Bitcoin-ABC/bitcoin-abc.git | make
```

# run 
Run bitcoin node in regtest mode to test localy.

```
$ bitcoind -regtest -printtoconsole -debug=1
```

Start applicatio with "bch-reg" network subcommand. Run with `--help` for details.

```
$ umbrella -vvvv bch-reg \
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
