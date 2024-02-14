#!/bin/bash

dir="./deployments/docker/build/"
[ ! -e $dir ] && echo must be executed from app root directory. && exit 1

[ -z "$1" ] && echo "1st argument must be the image name, e.g. defenxor/dsiem-rs" && exit 1
image_name=$1

tmpctx=$dir/ctx
mkdir -p $tmpctx
rsync -vhra --delete ./ $tmpctx/ --include='**.gitignore' --exclude='/.git' --exclude-from=<(git -C ./ ls-files --exclude-standard -oi --directory)

pkg="$tmpctx/Cargo.toml"
[ ! -f "$pkg" ] && echo $pkg isnt available && exit 1

version=$(grep version Cargo.toml | head -1 | cut -d\" -f2)

for v in version; do
  declare "${v}=$(grep ${v} $pkg | head -1 | cut -d\" -f2)"
  [ "${!v}" = "null" ] && echo cant read $v && exit 1
done

cd $dir

docker build -f Dockerfile -t $image_name:$version -t $image_name:latest . || exit 1

if [ "$2" == "push" ]; then
  echo pushing
  docker push $image_name:$version
  docker push $image_name:latest
fi
