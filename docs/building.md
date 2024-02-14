# Building from Source

## Requirements

- A Unix shell environment, with a working `git` and `docker` command.
- [Rust](https://www.rust-lang.org/tools/install) tools.
- Basic [NodeJs] 

## Steps

- Use `git` to clone this repository and `cd` into it.

- Make sure you have both `cargo` and `npm` in `$PATH`. These commands should work from all location:
  
  ```shell
  $ cargo version
  $ npm -v
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
  $ ./scripts/build-musl.sh
  ```
  
  The result will be in:
  - `./target/x86_64-unknown-linux-musl/release/dsiem-frontend`.
  - `./target/x86_64-unknown-linux-musl/release/dsiem-backend`.

- To build the web UI:
  
  ```shell
  $ ./scripts/build-web.sh prod
  ```
  The result will be in `./web/dist` directory.

- To build the docker image:

  ```shell
  $ ./scripts/dockerbuild.sh defenxor/dsiem-rs
  ```
  The result will be an image named `defenxor/dsiem-rs`.

