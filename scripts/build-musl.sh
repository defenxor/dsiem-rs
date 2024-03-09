#!/bin/bash

for cmd in git docker; do
  command -v $cmd >/dev/null 2>&1 || {
    echo ${cmd} command doesnt exist
    exit 1
  }
done

dir=$(git rev-parse --show-toplevel) || { echo "not in a git repo" && exit 1; }

cd $dir

exec docker run --rm -v $(pwd):/dsiem-rs -w /dsiem-rs -e OPENSSL_NO_VENDOR=Y mmta/rust-alpine-mimalloc sh -c "apk add libressl-dev && cargo build -p dsiem --release"
