# Dsiem-rs

[![CI](https://github.com/defenxor/dsiem-rs/actions/workflows/publish.yml/badge.svg)](https://github.com/defenxor/dsiem-rs/actions/workflows/publish.yml) 
[![codecov](https://codecov.io/gh/defenxor/dsiem-rs/graph/badge.svg?token=XC9ARCJAII)](https://codecov.io/gh/defenxor/dsiem-rs)

This is an implementation of [Dsiem](https://github.com/defenxor/dsiem) main binary and web UI in Rust. The goals are:

- Evaluate different runtimes (e.g. go vs tokio) specific to Dsiem use case.
- Identify optimization opportunities for the code in Dsiem main repo.
- Avoid Javascript framework maintenance burden by switching the web UI to WebAssembly.

## Documentation

Currently available docs are located [here](https://github.com/defenxor/dsiem-rs/tree/master/docs). They're based on the main repo docs with adjustments as needed.

## Differences with dsiem main repo binary

Compared to Dsiem in the main repo, this repo currently:

- Produces two separate binaries `dsiem-frontend` and `dsiem-backend` instead of one, and therefore doesn't support `standalone` mode.
- Replaces the Angular-based web UI with a WebAssembly built using the [Yew](https://yew.rs) framework.
- Doesn't include any of the Dsiem tools (e.g. Dpluger, nesd, etc.), but there shouldn't be compatibility issue to use the ones from the main repo.
- Support saving backlogs to disk before exiting, and reloading them after restart (controlled by `--reload-backlogs` flag, see below for more details).
- Discard out-of-order events by default, preventing them from creating a new backlog when there's already one in progress (controlled by `--discard-oor-events` flag, See below for more details).
- Has no support for Elastic APM. Future support for distributed tracing will likely use a more vendor-neutral platform.
- Requires all directives to be loaded without error during startup. The behaviour of the main repo binary which tries to fix minor errors, and skip loading (with a warning) directives that has major errors, is only practical during initial migration from OSSIM.
- Doesn't default to use JSON-lines log output (enable through `-j` parameter or `DSIEM_JSON=true` env. variable).
- Integrate `backlog` and `alarm` to one struct to reduce data duplication.
- Simplifies use of channels (with the assistance from async), particularly for backpressure control, backlog deletion, and stats reporting.
- Has overall simpler structure and easier to understand, partly because of the reduced features.

### Saving and reloading backlogs on restart

If `--reload-backlogs` flag or `DSIEM_RELOAD_BACKLOGS` environment variable is set to `true` (which is the default), then existing backlogs 
will be saved to `/logs/backlogs/{directive_id}.json` when dsiem-backend shuts down, and will be reloaded on the next run. The goal of this feature is to reduce the number of alarms that are recreated during configuration changes (directives, assets, etc.).

A couple of notes on this feature:

- A saved backlog that has a different title than the directive will be discarded. This is to prevent manager from loading a wrong backlog for a directive, which could happen if there's a change in directive ID assignment during down time.

- Backlogs loaded from disk will continue to use their previous rules, so any changes made to the directive rules during down time will only apply to new backlogs.
  Modify `/logs/backlogs/{directive_id}.json` during down time if there is a need to immediately apply updated rules to saved backlogs on next run, or just delete the file to discard all saved backlogs.

- All `/logs/backlogs/{directive_id}.json` files will be deleted on the next run regardless of whether the backlogs therein were successfully loaded or not. This is to prevent potential content error affecting the backend startup process.

- Saving is activated upon receiving `SIGTERM` signal. That includes commands like `docker restart` and `kill {PID}`. By contrast, `kill -9 {PID}` or any similar command which sends `SIGKILL` instead of `SIGTERM`, will not activate saving backlogs to disk.

### Discarding out-of-order events

Out-of-order events are those that match a backlog's current stage rule condition, but have an older timestamp than the last event of the previous stage. 

For example, on a directive with the following rules:

```json
{ "name": "ICMP Ping", "type": "PluginRule", "stage": 1, "plugin_id": 1001, "plugin_sid": [ 2100384 ], "occurrence": 1, ... },
{ "name": "ICMP Ping", "type": "PluginRule", "stage": 2, "plugin_id": 1001, "plugin_sid": [ 2100384 ], "occurrence": 100, ... },
{ "name": "ICMP Ping", "type": "PluginRule", "stage": 3, "plugin_id": 1001, "plugin_sid": [ 2100384 ], "occurrence": 1000, ... },
```

if the following events are sent to it one by one:

```json
{ "event_id": "1", "plugin_id": 1001, "plugin_sid": 2100384, "timestamp": "2024-02-16T03:01:00.019Z" }
{ "event_id": "2", "plugin_id": 1001, "plugin_sid": 2100384, "timestamp": "2024-02-16T03:00:00.019Z" }
{ "event_id": "3", "plugin_id": 1001, "plugin_sid": 2100384, "timestamp": "2024-02-16T03:02:00.019Z" }
{ "event_id": "4", "plugin_id": 1001, "plugin_sid": 2100384, "timestamp": "2024-02-16T03:03:00.019Z" }    
```

Then the following will happen:

- event `1` will trigger a new backlog creation.
- the backlog will move into the stage 2 since its stage 1 occurrence has been met.
- event `2` will be **ignored** by the backlog because its timestamp is older than event `1`, which was the last event accepted in previous stage.
- event `3` and `4` will be accepted into stage 2 without issue.

Accepting event `2` above doesn't make sense when it is older than the last event in stage 1. This is much more obvious in a directive with multiple `plugin_sid`. For example, for a directive that's intended to capture a successful login event followed by files deletion, we don't want to suspect an account to have deleted a file when the deletion happened before the login event.

Now, the question is how to deal with event `2` afterwards.

Backlogs created by [Dsiem in main repo](https://github.com/defenxor/dsiem) currently treat that event as unmatched, and therefore allow it to be use for triggering creation of a new backlog. This is certainly the case for directives that only use a single `plugin_sid` like the above example.

Dsiem-rs provides `--discard-oor-events` flag or `DSIEM_DISCARD_OOR_EVENTS` environment variable to control what to do in such cases. If the flag is set to `true` (the default), then those events will not be consider for creation of new backlog. Setting it to false will preserve Dsiem main repo's behavior.

## Replacing existing Dsiem installation

For docker/container environment:

Just replace your existing frontend and backend image location from `defenxor/dsiem` to `defenxor/dsiem-rs`. 

For non container environment:

Download `dsiem-server_linux_x86_64.zip` from the latest [Release](https://github.com/defenxor/dsiem-rs/releases), extract the binaries, and then use them to replace your existing Dsiem frontend and backends.  

In both cases, all frontend/backend specific environment variables are accepted and should work as intended.

