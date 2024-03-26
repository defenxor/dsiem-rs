# Building from Source

## Requirements

- A Unix shell environment, with a working `git` and `docker` command.
- [Rust](https://www.rust-lang.org/tools/install) tools.
- Basic [NodeJs](https://nodejs.org/en/download) environment for the CSS files.

## Steps

- Use `git` to clone this repository and `cd` into it.

- Make sure you have both `cargo` and `npm` in `$PATH`. These commands should work from all location:
  
  ```shell
  cargo version
  npm -v
  ```

- Open terminal and `cd` to dsiem-rs working directory.

- To build both `dsiem-backend` and `dsiem-frontend` binary:

  ```shell
  cargo build
  ```
  Results will be in:
  - `./target/debug/dsiem-frontend`
  - `./target/debug/dsiem-backend`

  Or to build the release version:

  ```shell
  ./scripts/build-glibc.sh
  ```
  
  The result will be in:
  - `./target/x86_64-unknown-linux-gnu/release/dsiem-frontend`.
  - `./target/x86_64-unknown-linux-gnu/release/dsiem-backend`.

- To build the web UI:
  
  ```shell
  ./scripts/build-web.sh prod
  ```
  The result will be in `./web/dist` directory.

## Building the docker image

  Use the helper script `dockerbuild.sh` as follows:
  ```shell
  ./scripts/dockerbuild.sh defenxor/dsiem-rs [base_image]
  ```

  Where base image can be one of `wolfi`, `alpine`, `ubuntu`, or `alpine_musl`.
  
  The result will be an image named `defenxor/dsiem-rs` with the appropriate tag. By-default, using `wolfi` will also tag the result as `latest`.

## Extra environment variables

  Both `build-glibc.sh` and `dockerbuild.sh` observe the following environment variables:
  
  - `DSIEM_DYNAMIC_LIBGCC`: if set, this will build binaries that are dynamically linked 
  to libgcc, which means the environment must provide a compatible version. The image produced by `dockerbuild.sh` should already fulfil this extra requirement.

  - `DSIEM_NIGHTLY_RUST`: if set, the build process will use rust nightly toolchain with a few extra options activated, namely [`build-std`](https://doc.rust-lang.org/cargo/reference/unstable.html#build-std) and [`sanitizer`](https://doc.rust-lang.org/beta/unstable-book/compiler-flags/sanitizer.html).
  
    > [!Note]
    > Sanitizer requires dynamically linked libgcc, so it will only be used if `DSIEM_DYNAMIC_LIBGCC` is set.

  Examples:
  
  ```shell
  DSIEM_DYNAMIC_LIBGCC=1 DSIEM_NIGHTLY_RUST=1 ./scripts/build-glibc.sh
  ```
  ```shell
  DSIEM_NIGHTLY_RUST=1 ./scripts/dockerbuild.sh defenxor/dsiem-rs alpine
  ```
