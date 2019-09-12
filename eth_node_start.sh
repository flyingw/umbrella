#!/bin/bash

# avoid network initialization

DATA_DIR="network1/"
VERBOSITY=7
PORT=30301
NETWORK_ID="123"
pub1="39f64d1564c9F110771DEBD039c22ef555b9F363" # cut from json in settings

printf ${PASS}'\n' | geth --datadir $DATA_DIR -verbosity $VERBOSITY --port $PORT --networkid $NETWORK_ID --unlock $pub1 --mine --nodiscover