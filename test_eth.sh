#! /bin/bash


NETWORK="eth"
NODE_KEY="d0bc33654a58f72301450f6146bd9b26501aad33f21dd9b3066769ef27da3c4a987db3fd70b27bbbca5e19a87bb9df094c167a8b1f77bb349dec27fdf665a1ae"
CRYPTO='{"cipher":"aes-128-ctr","ciphertext":"ad821681586cac20d4dac7a1becdf83bb67bc134f86b35eef69b8b89246ba0ac","cipherparams":{"iv":"8d4219c97f9d60750f8b050e75e5fc24"},"kdf":"scrypt","kdfparams":{"dklen":32,"n":262144,"p":1,"r":8,"salt":"fe0f103ab84cf273dd6d0c8b47db27735f32359d5ae6067b63ed4e554c75b97e"},"mac":"8dc0fce220979e970ccafea5690ce09754f93103e77de665938722fb00c784bd"}'
PASS="test"
OUT_ADDRESS="2217F561635a924F2C7ad1149Ca1dCf35Eaee961"
SECRET="426ab013650cbe3c615c2455fb414130ce45ca67e7205cb3104ec79a57ef1227"
VALUE="10"

  #--crypto $CRYPTO

RUST_BACKTRACE=1 cargo run -- $NETWORK \
  --pub_key $NODE_KEY \
  --secret $SECRET \
  --password $PASS \
  --out_address $OUT_ADDRESS \
  --dust_address "" \
  --dust_amount "0.0" \
  --value $VALUE \
  --data ""
