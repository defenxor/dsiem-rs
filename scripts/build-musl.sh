#!/bin/bash

for cmd in git docker; do
  command -v $cmd >/dev/null 2>&1 || {
    echo ${cmd} command doesnt exist
    exit 1
  }
done

dir=$(git rev-parse --show-toplevel) || { echo "not in a git repo" && exit 1; }

cd $dir

exec docker run --rm -v $(pwd):/home/rust/src messense/rust-musl-cross:x86_64-musl cargo build -p dsiem --release
