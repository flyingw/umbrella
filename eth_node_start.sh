#!/bin/bash

# avoid network initialization

DATA_DIR="network1/"
VERBOSITY=7
PORT=30301
NETWORK_ID="123"
pub1="f3f1125d9445748dea24b8e087a6419539c0e816" # cut from json in settings

printf ${PASS}'\n' | geth --datadir $DATA_DIR -verbosity $VERBOSITY --port $PORT --networkid $NETWORK_ID --unlock $pub1 --mine --nodiscover