# Commands and configuration

This repository builds `dsiem-frontend` and `dsiem-backend`. Each has a `serve` subcommand; there is no standalone mode. Tools such as `dpluger`, `dtester`, and `nesd` come from the [original Dsiem repository](https://github.com/defenxor/dsiem).

Read the options for the binary you installed:

```shell
./dsiem-frontend --help
./dsiem-frontend serve --help
./dsiem-backend --help
./dsiem-backend serve --help
```

`--test-env` selects repository fixtures for development tests and is not a deployment option.

Logging switches belong before `serve`, while server options follow it:

```shell
./dsiem-frontend --debug --json serve --node dsiem-frontend-0 --msq nats://localhost:4222
./dsiem-backend --json serve --node dsiem-backend-0 --frontend http://localhost:8080 --msq nats://localhost:4222
```

`--node` is required on both binaries unless `DSIEM_NODE` is set. Environment variable names are declared explicitly; they cannot always be inferred from a flag's spelling. `DSIEM_MODE` is used by the container launcher to select a binary, not by either binary itself.

## Shared options

| Option | Environment variable | Default / behavior |
| --- | --- | --- |
| `--debug` | `DSIEM_DEBUG` | `false`; debug logging |
| `--trace` | `DSIEM_TRACE` | `false`; trace logging; debug takes precedence if both are enabled |
| `-j`, `--json` | `DSIEM_JSON` | `false`; JSON-lines diagnostic logs |
| `-v`, `--verbosity` | None | Repeat for higher verbosity |
| `--node` | `DSIEM_NODE` | Required node name |
| `--msq` | `DSIEM_MSQ` | `nats://dsiem-nats:4222` |
| `--max_eps` | `DSIEM_MAXEPS` | `1000`; frontend acceptance limit, backend expected rate for sizing and timing |
| `--max_queue` | `DSIEM_MAXQUEUE` | Frontend: `25000`; backend: `32768` |
| `--status` | `DSIEM_STATUS` | `Open,In-Progress,Closed` |
| `--tags` | `DSIEM_TAGS` | `Identified Threat,False Positive,Valid Threat,Security Incident` |
| `--otel-tracing-enabled` | `DSIEM_OTEL_TRACING_ENABLED` | `false` |
| `--otel-endpoint` | `DSIEM_OTEL_ENDPOINT` | `http://localhost:4317`; OTLP gRPC |

The frontend writes status/tag choices for the UI. Backends use the first status and tag as defaults for new alarms. Configure both sides consistently.

`max_queue=0` maps to 524,288 in both binaries. Tokio broadcast channels round capacity to a power of two; other queues have their own limits. A zero setting does not create an unlimited queue. See [Managing performance](managing_performance.md).

Boolean switches can be enabled on the command line without a value, for example `--preload-all-directives`. Use their environment variables with `true` or `false` to set them explicitly. In particular, set `DSIEM_RELOAD_BACKLOGS=false` to disable the default restart recovery.

## Frontend options

| Option | Environment variable | Default |
| --- | --- | --- |
| `--ip-address` | `DSIEM_ADDRESS` | `0.0.0.0` |
| `--tcp-port` | `DSIEM_PORT` | `8080` |
| `--min_eps` | `DSIEM_MINEPS` | `100` |
| `--writable-config` | `DSIEM_WRITEABLECONFIG` | `false`; enables HTTP configuration upload/deletion |

Use positive frontend limits with `min_eps <= max_eps`. Although the limiter constructor treats zero as disabled, the background adjustment task currently requires an initialized limiter. Use a positive backend `max_eps` too; backend allocation and wait-time calculations depend on it.

## Backend options

| Option | Environment variable | Default / behavior |
| --- | --- | --- |
| `--frontend` | `DSIEM_FRONTEND` | `http://frontend:8080`; HTTP URL used to download configuration |
| `--min-alarm-lifetime` | `DSIEM_MINALARMLIFETIME` | `0` minutes; adds time to the current rule's expiration deadline |
| `--med_risk_min` | `DSIEM_MEDRISKMIN` | `3` |
| `--med_risk_max` | `DSIEM_MEDRISKMAX` | `6` |
| `--cache` | `DSIEM_CACHEDURATION` | Accepted with default `10`, but currently not used by the lookup caches |
| `--hold_duration` | `DSIEM_HOLDDURATION` | `10` seconds before clearing an overload signal |
| `--max_delay` | `DSIEM_MAXDELAY` | `180` seconds; `0` disables backlog delay signaling |
| `--intel_private_ip` | `DSIEM_INTELPRIVATEIP` | `false`; include non-global IPs in intel lookups when enabled |
| `--reload-backlogs` | `DSIEM_RELOAD_BACKLOGS` | `true`; save and restore backlogs across graceful restart |
| `--otel-metrics-enabled` | `DSIEM_OTEL_METRICS_ENABLED` | `false` |
| `--filter-threads` | `DSIEM_FILTER_THREADS` | `0`; calculate allocation automatically |
| `--preload-all-directives` | `DSIEM_PRELOAD_DIRECTIVES` | `false`; start all backlog managers at startup |
| `--idle-directives-timeout` | `DSIEM_DIRECTIVES_IDLE_TIMEOUT_MINUTES` | `10` minutes; minimum `5`; applies to on-demand managers |

Lookup caches are currently configured in code with a 30-minute time-to-live and a 5-minute time-to-idle. See [lookup plugins](ti_vuln_plugins.md).

The authoritative declarations are in [dsiem-frontend.rs](../server/src/bin/dsiem-frontend.rs) and [dsiem-backend.rs](../server/src/bin/dsiem-backend.rs). Shared runtime transformations are in [cmd_utils.rs](../server/src/cmd_utils.rs).
