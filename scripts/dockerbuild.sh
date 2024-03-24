#!/bin/bash

# usage:

# 1st argument: image name, e.g. defenxor/dsiem-rs
# 2nd argument: must be one of "alpine", "alpine_musl", "ubuntu", "wolfi"
# 3rd argument: optional, if equals to "push" the image will be pushed to the registry

# if 2nd argument is the same as env variable DEFAULT_BASE_IMAGE, the image will be tagged as "latest"
# the default for DEFAULT_BASE_IMAGE for now is "wolfi"

# if env variable DSIEM_DYNAMIC_LIBGCC is set, glibc will be linked dynamically (except for "alpine_musl")
# if env variable DSIEM_NIGHTLY_RUST is set, the nightly version of rust will be used

dir="./deployments/docker/build"
[ ! -e $dir ] && echo must be executed from the repo root directory. && exit 1

DEFAULT_BASE_IMAGE=${DEFAULT_BASE_IMAGE:-wolfi}

DSIEM_DYNAMIC_LIBGCC=${DSIEM_DYNAMIC_LIBGCC:-""}
DSIEM_NIGHTLY_RUST=${DSIEM_NIGHTLY_RUST:-""}

image_name=$1
base_image=$2

([ "$2" == "alpine" ] || [ "$2" == "ubuntu" ] || [ "$2" == "wolfi" ]) && musl="false"
[ "$2" == "alpine_musl" ] && musl="true"
[ "$3" == "push" ] && push_image=true

[ -z "$image_name" ] && echo "1st argument must be the image name, e.g defenxor/dsiem-rs" && exit 1
[ -z "$musl" ] && echo "2nd argument must be one of 'alpine', 'alpine_musl', 'ubuntu', 'wolfi'" && exit 1

[ "$musl" == "true" ] && dsiem_lib="_musl"

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

mkdir -p $tmpctx/scripts && cp ./scripts/build-glibc.sh $tmpctx/scripts/build-glibc.sh

pkg="$tmpctx/Cargo.toml"
[ ! -f "$pkg" ] && echo $pkg isnt available && exit 1
version=$(grep version Cargo.toml | head -1 | cut -d\" -f2)

build_image() {
  local dockerfile=$1
  local image_name=$2
  local extra_arg=$3
  echo building $image_name ..
  docker build -f ${dockerfile} -t ${image_name} ${extra_arg} . || {
    echo "failed building image"
    exit 1
  }
}

cd $dir/

# dsiem-dev/webui-builder
build_image 01.webui-builder dsiem-dev/webui-builder

# dsiem-dev/server-builder

[ "$DSIEM_DYNAMIC_LIBGCC" ] &&
  libgcc_arg="--build-arg apk_extra_packages=libgcc --build-arg DSIEM_DYNAMIC_LIBGCC=1" &&
  alpine_arg="--build-arg alpine_base=mmta/alpine-glibc" ||
  alpine_arg="--build-arg alpine_base=alpine"

[ "$DSIEM_NIGHTLY_RUST" ] &&
  nightly_arg="--build-arg DSIEM_NIGHTLY_RUST=1"

build_image 02.server-builder${dsiem_lib} dsiem-dev/server-builder "${libgcc_arg} ${nightly_arg}"

# dsiem-dev/base-image
build_image 03.base-${base_image} dsiem-dev/base-image "${libgcc_arg} ${alpine_arg}"

this_image=${image_name}:${version}-${base_image}

# dsiem-rs
build_image Dockerfile ${this_image}

[ "$latest_tag" == "true" ] &&
  echo tagging ${this_image} as ${image_name}:${version} and ${image_name}:latest &&
  docker tag ${this_image} $image_name:$version &&
  docker tag ${this_image} $image_name:latest

if [ "$push_image" == "true" ]; then
  docker push ${this_image}
  [ "$latest_tag" == "true" ] && docker push $image_name:$version && docker push $image_name:latest
fi
