#!/bin/bash

# usage:
# 1st argument: image name, e.g. defenxor/dsiem-rs
# 2nd argument: musl (optional) or push (optional)
# 3rd argument: push (optional), if 2nd argument is musl

dir="./deployments/docker/build/"
[ ! -e $dir ] && echo must be executed from app root directory. && exit 1

[ -z "$1" ] && echo "1st argument must be the image name, e.g. defenxor/dsiem-rs" && exit 1
([ "$1" == "musl" ] || [ "$1" == "push" ]) && echo "1st argument must be the image name, e.g. defenxor/dsiem-rs" && exit 1

image_name=$1

[ "$2" == "musl" ] && musl=true && [ "$3" == "push" ] && push_image=true
[ "$2" == "push" ] && push_image=true

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

[ "$musl" == "true" ] && dockerfile=Dockerfile.musl || dockerfile=Dockerfile
[ "$musl" == "true" ] && version=${version}-musl

echo building $image_name:$version

docker build -f ${dockerfile} -t $image_name:$version . || exit 1

[ "$musl" != "true" ] && docker tag $image_name:$version $image_name:latest

if [ "$push_image" == "true" ]; then
  echo pushing
  docker push $image_name:$version
  [ "$musl" != "true" ] && docker push $image_name:latest
fi
