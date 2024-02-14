#!/bin/bash

# requirement: sudo apt install lcov

dir="./coverage"

for cmd in lcov genhtml; do
  command -v $cmd &>/dev/null || {
    echo ${cmd} command doesnt exist
    exit 1
  }
done

mkdir -p $dir
genhtml -o $dir $dir/lcov.info

[ "$1" == "serve" ] && {
  cd $dir
  python3 -m http.server $2
} || exit 0
