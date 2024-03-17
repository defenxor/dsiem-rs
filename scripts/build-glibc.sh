#!/bin/bash

dir=$(git rev-parse --show-toplevel) || { echo "not in a git repo" && exit 1; }

cd $dir

RUSTFLAGS="-C target-feature=+crt-static" cargo build --target x86_64-unknown-linux-gnu --release
