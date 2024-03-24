#!/bin/bash

# usage example:

# - build with stable toolchain and static linking to glibc:
#   scripts/build-glibc.sh

# - build with nightly toolchain and dynamic linking to glibc:
#   DSIEM_DYNAMIC_LIBGCC=1 DSIEM_NIGHTLY_RUST=1 scripts/build-glibc.sh

# - build specific binary:
#   scripts/build-glibc.sh --bin dsiem-backend

grep -q Dsiem ./Cargo.toml 2>/dev/null || { echo "not in the root of the project" && exit 1; }

# defaults to static build and stable toolchain unless overriden using these

[ "$DSIEM_DYNAMIC_LIBGCC" ] && target_feature="-crt-static" || target_feature="+crt-static"
[ "$DSIEM_NIGHTLY_RUST" ] &&
  nightly="+nightly" &&
  option_z="-Zlocation-detail=none" &&
  build_std="-Z build-std=std,panic_abort -Z build-std-features=panic_immediate_abort" &&
  ([ "$DSIEM_DYNAMIC_LIBGCC" ] && option_z="${option_z} -Zsanitizer=address" || true)

set -x

RUSTFLAGS="-C target-feature=${target_feature} ${option_z}" \
  cargo ${nightly} build ${build_std} --target x86_64-unknown-linux-gnu --release $@
