# Didactic Umbrella

Imaginary name for a project wich in other hand will be called literaly project.

# Idea

Light command line interface to some restricted blockchains API.

# Download

[v0.1.0] (http://didactic.umbrella/)

# Prerequisites

Setup Rust

```
$ curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
$ rustup update
```

Setup Bitcoin Node and CLI tools

```
$ brew install bitcoin
```

# Build 

```
$ cargo build
```

[describe native build configuration here]

Possible config? Need to know what its means for building process.

```
$HOME/.cargo $ cat config
[build]
rustflags = "-C target-cpu=native"

$ cargo update
$ cargo build --release
```
look for binaries at `./target/releases`

# Run 

Run bitcoin node in regtest mode to test connection localy.
Actually all test connections will work but this need to be changed in code.

```
$ bitcoind -regtest
```

```
$ cargo run -- -vvvv [optional parameters: -v, -network, etc.] [--help: for details]
```

# Dev Notes

Project uses external `BCH` client for demo purposess. 
Since its distributed as source code on github `cargo` patch this project for us. 

Check `$HOME/.cargo` folder for downloaded repository with source code or 
checkout it manually and patch `crates.io` with `path='./local/path'`.

git@github.com:marioschlipf/bitcoin-abe.git
