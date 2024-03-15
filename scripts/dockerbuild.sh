#!/bin/bash

# usage:
# 1st argument: image name
# 2nd argument: must be one of "alpine_glibc", "alpine_musl", "ubuntu_glibc"
# 3rd argument: if equals to "push", the image will be pushed to the registry

# if 2nd argument is the same as env variable DEFAULT_BASE_IMAGE, the image will be tagged as "latest"

dir="./deployments/docker/build"
[ ! -e $dir ] && echo must be executed from the repo root directory. && exit 1

DEFAULT_BASE_IMAGE=${DEFAULT_BASE_IMAGE:-alpine_glibc}

image_name=$1
base_image=$2

([ "$2" == "alpine_glibc" ] || [ "$2" == "ubuntu_glibc" ]) && dsiem_lib="glibc"
[ "$2" == "alpine_musl" ] && dsiem_lib="musl"
[ "$3" == "push" ] && push_image=true

[ -z "$image_name" ] && echo "1st argument must be the image name, e.g dsiem-dev/dsiem-rs" && exit 1
[ -z "$dsiem_lib" ] && echo "2nd argument must be one of 'alpine_glibc', 'alpine_musl', 'ubuntu_glibc'" && exit 1

[ "$DEFAULT_BASE_IMAGE" == "$base_image" ] && latest_tag=true

echo "image name: $image_name"
echo "base image: $base_image"

tmpctx=$dir/ctx
mkdir -p $tmpctx
rsync -vhra --delete ./ $tmpctx/ \
  --include='**.gitignore' \
  --exclude='/.git' \
  --exclude="/.github" \
  --exclude="/deployments" \
  --exclude="/fixtures" \
  --exclude="/demo" \
  --exclude="/docs" \
  --exclude='/scripts' \
  --exclude='Dockerfile' \
  --exclude-from=<(git -C ./ ls-files --exclude-standard -oi --directory)

pkg="$tmpctx/Cargo.toml"
[ ! -f "$pkg" ] && echo $pkg isnt available && exit 1
version=$(grep version Cargo.toml | head -1 | cut -d\" -f2)

build_image() {
  local dockerfile=$1
  local image_name=$2
  echo building $image_name ..
  docker build -f ${dockerfile} -t ${image_name} . || {
    echo "failed building image"
    exit 1
  }
}

cd $dir/

# dsiem-dev/webui-builder
build_image 01.webui-builder dsiem-dev/webui-builder

# dsiem-dev/server-builder
build_image 02.server-builder_${dsiem_lib} dsiem-dev/server-builder

# dsiem-dev/base-image
build_image 03.base-${base_image} dsiem-dev/base-image

this_image=${image_name}:${version}-${base_image}

# dsiem-rs
build_image Dockerfile ${this_image}

[ "$latest_tag" == "true" ] &&
  echo tagging ${this_image} as ${image_name}:${version} and ${image_name}:latest &&
  docker tag ${this_image} $image_name:$version &&
  docker tag ${this_image} $image_name:latest

if [ "$push_image" == "true" ]; then
  docker push ${this_image}
  [ "$latest_tag" == "true" ] && docker push $image_name:$version $image_name:latest
fi
