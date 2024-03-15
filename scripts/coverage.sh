#!/bin/sh

root=$(git rev-parse --show-toplevel)
cd $root

mkdir -p ./coverage

# default to nextest
tester="nextest"
[ "$1" = "test" ] && tester="test"

# only target the dsiem package
exec cargo llvm-cov ${tester} -p dsiem --lcov --output-path ./coverage/lcov.info
