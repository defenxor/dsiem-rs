#!/bin/bash

package=$1
bin_or_lib=$2
bin_name=$3
shift 3
tests=$@

[ "$package" = "" ] && echo "Package name is required" && exit 1
[ "$bin_or_lib" = "" ] && echo "Binary or library is required" && exit 1
[ "$bin_name" = "" ] && echo "Binary name is required" && exit 1
[ "$tests" = "" ] && echo "Test names are required" && exit 1

exec cargo watch -x "llvm-cov -p ${package} --lcov --output-path ./coverage/lcov-add.info --${bin_or_lib} ${bin_name} nextest ${tests}"
