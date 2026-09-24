# Filter comparison

This separate Cargo workspace compares Rayon with dedicated threads for directive quick checks. It starts an HTTP listener at `127.0.0.1:6667` and logs queue length and matching-directive counts. It does not run backlogs or create alarms. Performance depends on the supplied directives, events, and hardware.

## Build and configure

From the repository root:

```shell
cargo build --locked --release --manifest-path scripts/filter-comparison/Cargo.toml
mkdir -p scripts/filter-comparison/target/release/configs
cp configs/directives_dsiem-backend-0_testing1.json scripts/filter-comparison/target/release/configs/directives_testing.json
```

Use a larger directive set to measure sustained filtering work. Configuration is loaded from `configs/` beside the executable and filenames must match `directives_*.json`. A file named only `directive.json` is not loaded. Each directive must pass the server's normal validation.

If you set `CARGO_TARGET_DIR`, use its release directory for both the binary and the adjacent `configs/` directory instead.

## Run a comparison

```shell
USE_RAYON=false DIRECTIVES_PER_THREAD=5000 scripts/filter-comparison/target/release/filter-comparison
```

Stop that process before trying Rayon on the same port:

```shell
USE_RAYON=true RAYON_THREAD_POOL_SIZE=4 scripts/filter-comparison/target/release/filter-comparison
```

`USE_RAYON` defaults to `false`, `DIRECTIVES_PER_THREAD` to 5000, and `RAYON_THREAD_POOL_SIZE` to 4. Keep thread counts and directives-per-thread positive.

Send normalized event objects to `http://127.0.0.1:6667/events/`. The [external dtester tool](https://github.com/defenxor/dsiem/tree/master/cmd/dtester) can generate a stream from directive data; check its installed help for command syntax. Use the same event stream and directive set for both modes, then compare queue growth and processing behavior.
