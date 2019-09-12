#! /bin/bash

# start ethereum private network for testing
# go ethereum client required:
# `brew install ethereum`

NAME="network1"
NETWORK_ID="123"
DIR="accounts/"
DATA_DIR="${NAME}/"
VERBOSITY=3
PORT=30301
PASS="test"

rm ~/.puppeth/$NAME
rm -r $DIR
rm -r $DATA_DIR

acc=$(printf ${PASS}'\n'${PASS}'\n' | geth -datadir $DIR account new)
pub1=$(grep 'Public address of the key' <<< "$acc" | cut -f2 -d: |cut -c 6-)
sec1=$(grep 'Path of the secret key file' <<< "$acc" |cut -f2 -d:|cut -c 2-)

acc1=$(printf ${PASS}'\n'${PASS}'\n' | geth -datadir $DIR account new)
pub2=$(grep 'Public address of the key' <<< "$acc1" | cut -f2 -d: |cut -c 6-)
sec2=$(grep 'Path of the secret key file' <<< "$acc1" |cut -f2 -d:|cut -c 2-)

echo "seal: $pub1, $sec1"
echo "fund: $pub2, $sec2"

printf ${NAME}'\n2\n1\n2\n15\n'${pub1}'\n\n'${pub2}'\n\nyes\n'${NETWORK_ID}'\n2\n2\n\n' | puppeth

geth --datadir $DATA_DIR init network1.json

rm "${NAME}.json"
rm "${NAME}-harmony.json"

mv $DIR/keystore $DATA_DIR
rm -r $DIR

# immidiately shutdown if started with console
# find out why or
# attach console later with `geth attach --datadir $DATA_DIR`

printf ${PASS}'\n' | geth --datadir $DATA_DIR -verbosity $VERBOSITY --port $PORT --networkid $NETWORK_ID --unlock $pub1 --mine --nodiscover
