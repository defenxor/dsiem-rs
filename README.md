# Dsiem-rs

[![CI](https://github.com/defenxor/dsiem-rs/actions/workflows/publish.yml/badge.svg)](https://github.com/defenxor/dsiem-rs/actions/workflows/publish.yml)
[![codecov](https://codecov.io/gh/defenxor/dsiem-rs/graph/badge.svg?token=XC9ARCJAII)](https://codecov.io/gh/defenxor/dsiem-rs)

Dsiem-rs is the Rust implementation of [Dsiem](https://github.com/defenxor/dsiem), an OSSIM-style security event correlation engine. It receives normalized events, tracks configured detection rules, and writes alarms with links to their supporting events. The included browser UI reads alarm data from Elasticsearch; the deployment examples use Filebeat, Logstash, and Kibana around the engine.

The Rust project was started to compare runtime behavior with the Go implementation, find optimization opportunities, and move the browser UI to WebAssembly to reduce JavaScript framework maintenance.

## Documentation

Start with the [documentation index](docs/README.md). These pages describe the Rust implementation and the deployment files in this repository.

## Implementation

- Separate `dsiem-frontend` and `dsiem-backend` binaries communicate through NATS. There is no standalone mode.
- The browser UI uses Rust, WebAssembly, and Yew.
- The workspace does not include the original Dsiem tools such as `dpluger`, `dtester`, or `nesd`. Obtain those separately and check their installed versions when following tool examples.
- Dedicated threads perform initial event filtering. Backlog managers start on demand by default, or can all be preloaded. See [managing performance](docs/managing_performance.md).
- Enabled directives must load without error at startup; `disabled` directives are skipped.
- OpenTelemetry provides optional tracing and metrics. See [telemetry](docs/telemetry.md).
- Diagnostic logs are plain text by default. Use `--json` before `serve` or set `DSIEM_JSON=true` for JSON-lines logs. Alarm output files always use JSON lines.

## Saving and reloading backlogs on restart

With restart recovery enabled (the binary default), active backlogs are saved to `logs/backlogs/{directive_id}.json` beside the backend executable (`/dsiem/logs/backlogs/` in the container) when dsiem-backend shuts down, and restoration is attempted on the next run. Set `DSIEM_RELOAD_BACKLOGS=false` to disable this behavior. The goal of this feature is to reduce the number of alarms that are recreated during configuration changes (directives, assets, etc.).

Recovery has these limits:

- A saved backlog that has a different title than the directive will be discarded. This is to prevent manager from loading a wrong backlog for a directive, which could happen if there's a change in directive ID assignment during down time. Note that this means backlogs generated of legacy OSSIM directives that have `SRC_IP` and `DST_IP` in title will always be discarded.

- Backlogs loaded from disk will continue to use their previous rules, so any changes made to the directive rules during down time will only apply to new backlogs.
  Modify `logs/backlogs/{directive_id}.json` during down time if there is a need to immediately apply updated rules to saved backlogs on next run, or just delete the file to discard all saved backlogs.

- Each snapshot file is removed after it has been read, before JSON parsing or backlog restoration succeeds. Files for directives that are not loaded are not automatically removed. Keep a backup before restarting if you need to inspect or retry a snapshot.

- Saving is activated during graceful shutdown, including handled `SIGTERM` and `SIGINT` signals. That includes commands like `docker restart` and `kill {PID}`. By contrast, `kill -9 {PID}` or any similar command which sends `SIGKILL` instead of `SIGTERM`, will not activate saving backlogs to disk.

## Replacing existing Dsiem installation

For Docker deployments, use `defenxor/dsiem-rs` for both frontend and backend containers. Set `DSIEM_MODE` to `cluster-frontend` or `cluster-backend` and provide `DSIEM_NODE`. A standalone deployment must be split into frontend, NATS, and backend services. See the [Compose example](deployments/docker/docker-compose.yml).

For a manual installation:

Download `dsiem-server_linux_x86_64.zip` from the latest [Release](https://github.com/defenxor/dsiem-rs/releases), extract the binaries, and then use them to replace your existing Dsiem frontend and backends.

Check environment variables against the [Rust command reference](docs/commands.md). Compatibility is not exact: for example, `DSIEM_CACHEDURATION` is accepted but does not control the current lookup caches. The supplied Compose examples also set `DSIEM_RELOAD_BACKLOGS=false`, overriding the binary default.

