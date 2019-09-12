#! /bin/bash


NETWORK="eth"

RUST_BACKTRACE=1 cargo run -- $NETWORK \
  -secret ...