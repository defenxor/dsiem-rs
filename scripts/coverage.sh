#!/bin/sh

root=$(git rev-parse --show-toplevel)
cd $root

mkdir -p ./coverage

# only target the dsiem package
exec cargo llvm-cov -p dsiem --lcov --output-path ./coverage/lcov.info
