# Building from source

Run the commands below from the repository root unless another directory is shown.

## Server binaries

Install Rust and a native compiler/linker for your platform. Docker and Node.js are not required for a native server build.

```shell
cargo build --locked --bins
```

The workspace defaults to the server package. The binaries are `target/debug/dsiem-frontend` and `target/debug/dsiem-backend`. For an optimized native build:

```shell
cargo build --locked --release --bins
```

The optimized binaries are under `target/release/`.

The [glibc helper](../scripts/build-glibc.sh) explicitly targets Linux x86-64:

```shell
./scripts/build-glibc.sh
```

It writes to `target/x86_64-unknown-linux-gnu/release/`. Run it in a Linux build environment with that target and its linker available; it does not install a cross-compilation toolchain on macOS or another host.

A compiled server binary needs runtime files beside the executable. Prepare `configs/` for each process, backend `logs/`, and frontend `web/dist/` as described in [installation](installation.md). The current working directory is not the runtime data root.

## Browser UI

The UI needs Rust, the WebAssembly target, Trunk, and Node.js/npm for CSS. The [Docker UI builder](../deployments/docker/build/01.webui-builder) uses Trunk 0.21.14 and Tailwind CSS 3. To follow that setup locally:

```shell
cargo install --locked trunk --version 0.21.14
rustup target add wasm32-unknown-unknown
cd web
npm init -y
npm install text-spinners@1.0.5
npx --yes --package tailwindcss@3 tailwindcss -c ./tailwind.config.js -o ./tailwind.css --minify
trunk build --public-url /ui --release true index.html
```

The result is `web/dist/`. Supply `web/dist/assets/config/esconfig.json` separately for runtime access to Elasticsearch and Kibana. See [UI development](../web/readme.md) for a live development server.

The repository also has `scripts/build-web.sh prod`, which calls `scripts/css.sh` before Trunk. That CSS helper installs unpinned Tailwind packages, unlike the Docker build, so it does not provide the same version selection as the commands above. Its `dev` path starts a CSS watcher before reaching Trunk; use separate watcher and Trunk terminals as described in the UI guide.

## Docker image

Install Docker, Git, Bash, and `rsync`, then run:

```shell
./scripts/dockerbuild.sh defenxor/dsiem-rs wolfi
```

The second argument is required and must be `wolfi`, `alpine`, `ubuntu`, or `alpine_musl`. The helper builds the intermediate images used by the final Dockerfile. The supplied image build targets Linux x86-64.

The result is tagged `<image>:<workspace-version>-<base>`. The base selected by `DEFAULT_BASE_IMAGE` (default `wolfi`) is also tagged with the bare version and `latest`. An optional third argument, `push`, publishes those tags to the registry.

## Build environment variables

`build-glibc.sh` and the glibc path in `dockerbuild.sh` recognize:

- `DSIEM_DYNAMIC_LIBGCC`: any nonempty value selects `-crt-static` instead of `+crt-static`. The binary then needs the corresponding dynamic runtime libraries, not only libgcc.
- `DSIEM_NIGHTLY_RUST`: any nonempty value selects nightly Rust and the script's `build-std` options. Address sanitizer is added when `DSIEM_DYNAMIC_LIBGCC` is also set. A local nightly build needs the nightly toolchain and `rust-src` component.

For example:

```shell
DSIEM_DYNAMIC_LIBGCC=1 DSIEM_NIGHTLY_RUST=1 ./scripts/build-glibc.sh
```

Unset these variables to disable their behavior; setting them to `0` still leaves them nonempty. The `alpine_musl` Docker path uses its own builder and does not use these glibc options.
