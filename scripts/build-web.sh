#!/bin/sh

[ "$1" != "prod" ] && [ "$1" != "dev" ] && echo need prod or dev as 1st argument && exit 1
mode=$1

for cmd in git trunk; do
  command -v $cmd >/dev/null 2>&1 || {
    echo ${cmd} command doesnt exist
    exit 1
  }
done

root=$(git rev-parse --show-toplevel) || {
  echo "not in a git repo"
  exit 1
}

cd $root/web

index="index.dev.html"
[ "$mode" = "prod" ] && rel_flag="--release" && public="--public-url /ui" && index="index.html"

$root/scripts/css.sh $mode &&
  echo "** building wasm $mode version" &&
  trunk build $public $rel_flag $index
