#!/bin/bash

package=$1
bin_or_lib=$2
bin_name=$3

[ "$package" = "" ] && echo "Package name is required" && exit 1
[ "$bin_or_lib" = "" ] && [ "$bin_or_lib" != "bin" ] && [ "$bin_or_lib" != "lib" ] && echo "'bin' or 'lib' is required" && exit 1
[ "$bin_or_lib" = "bin" ] && ([ "$bin_name" = "" ] && echo "Binary name is required" && exit 1 || shift 3)
[ "$bin_or_lib" = "lib" ] && bin_name="" && shift 2

tests=$@

[ "$tests" = "" ] && echo "Test names are required" && exit 1

exec cargo watch -x "llvm-cov -p ${package} --lcov --output-path ./coverage/lcov-add.info --${bin_or_lib} ${bin_name} nextest ${tests}"
