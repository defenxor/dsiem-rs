#!/bin/bash

dir=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" &>/dev/null && pwd)
cd $dir
shopt -s extglob
rm -rf -- !(get.sh|.gitignore)

# get the demo files from dsiem main repo
git clone --no-checkout --depth 1 --single-branch https://github.com/defenxor/dsiem &&
  cd dsiem &&
  git config core.sparseCheckout true &&
  echo demo >.git/info/sparse-checkout &&
  git checkout master &&
  cd .. &&
  mv dsiem/demo/* ./ &&
  rm -rf dsiem

# patch docker-compose
compose_file="docker/docker-compose.yml"
for line in $(grep -n dsiem:latest ${compose_file} | cut -d: -f1); do
  above=$((line - 1))
  cont_name=$(echo $(sed -n ${above}p ${compose_file} | cut -d: -f2))
  if [ "$cont_name" == "dsiem-backend" ]; then
    sed -i "${line}s/defenxor\/dsiem/defenxor\/dsiem-rs/" ${compose_file}
    patched="yes"
    break
  fi
done

[ -z "$patched" ] && echo "** cannot find dsiem-backend line to patch in ${compose_file}" ||
  echo "** ${compose_file} patched"
