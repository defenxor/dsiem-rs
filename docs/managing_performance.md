# Managing performance

Dsiem uses dedicated filter threads followed by asynchronous backlog managers. Monitor both parts of that path before changing resource allocation. Slow enrichment endpoints can also delay backlog processing.

## Filter allocation

The [allocator](../server/src/allocator.rs) estimates filter capacity using a constant of 100 million quick checks per thread per second, based on a cached benchmark on an i7-12700F. It combines the directive count and backend `max_eps` to choose the allocation. This is a sizing heuristic, not a measured throughput guarantee for your deployment.

For example, the estimate gives one thread for 20,000 directives at 5,000 events per second. The process requires at least two available logical CPUs and reserves at least one for Tokio. If the calculated filter allocation exceeds available parallelism, startup fails.

`DSIEM_FILTER_THREADS` or `--filter-threads` overrides the estimate. Leave at least one CPU for Tokio, and do not request more filter threads than there are directives. Measure actual queue growth and processing time after each change.

## Manager loading

All directive definitions are loaded and validated at startup. By default, backlog managers are started only when an event passes their directive's quick check. An idle manager with no backlogs is unloaded after `--idle-directives-timeout` minutes (default 10, minimum 5).

`--preload-all-directives` starts all managers immediately and keeps them loaded. This uses more memory but avoids repeated manager startup. Compare the modes with your directive set and event stream before selecting one for a throughput target.

## Queues and backpressure

Both binaries accept `--max_queue`. Defaults are 25,000 for the frontend and 32,768 for the backend. Tokio broadcast channels round capacity to a power of two. Other channels and the NATS subscription have their own capacities.

Setting `max_queue=0` selects a finite capacity of 524,288 events for compatibility with the original implementation. It also selects the backend manager's longer wait mode. Prefer an explicit capacity sized for the workload; zero is not an unlimited queue or a lossless-delivery setting.

When a broadcast receiver falls behind, it skips older retained events and reports lag. NATS can also lose messages for slow subscribers. Increasing a queue can absorb a burst, but cannot fix sustained processing demand above capacity.

Backlogs compare an event's frontend receipt time with the current time. If delay exceeds backend `--max_delay` (default 180 seconds), they send an overload signal through NATS. Frontends adjust their acceptance rate between `min_eps` and `max_eps` and return HTTP 429 when the limiter has no capacity. This checks processing transit time, not the original event timestamp.

`max_delay=0` disables these backlog overload signals; it does not disable the frontend's configured rate limiter. Set positive frontend limits with `min_eps <= max_eps`. Backend `max_eps` is an expected rate used for thread allocation and processing wait budgets, rather than a second HTTP acceptance limit.

Backpressure reduces intake but does not guarantee that every event is processed, or that concurrent processing preserves input order. Configure producer retries and buffering separately. Do not use these queues as the only durable record of security events.

## Reducing work

- Send normalized events to Dsiem only when its directives use them. Keep the original logs in the storage pipeline as needed.
- Split exclusive directive sets across backends on different hardware when a single host lacks capacity. Every backend still receives the full NATS event stream.
- Investigate slow or unreachable enrichment APIs when backlog processing time rises.
- Keep the main Elasticsearch ingestion path separate from Dsiem delivery if correlation downtime must not block log storage. The shipped single-pipeline example does not provide that isolation.

See [advanced deployment](adv_deployment.md) for backend assignments. The external `dpluger` tool has pipeline-generation options; check the installed tool's help before using them.

## Detecting performance issues

Enable JSON diagnostic logs with `DSIEM_JSON=true`, then inspect watchdog reports and lag messages:

```shell
docker logs -f dsiem-backend --since=5m | jq --unbuffered -c 'select(.target == "dsiem::watchdog" or (.fields.message // "" | contains("lagged")))'
```

Watch `queue_length` over time alongside `avg_proc_time_ms`, `directives_active`, `backlogs`, and `backlogs_timedout`. A growing queue indicates that consumers are falling behind. A `filtering lagged and skipped ... events` message confirms loss at that receiver.

The watchdog warns when the receive queue is nonempty and average processing time exceeds `1000 / max_eps` milliseconds. `backlogs_timedout` describes manager response waits; it is not a count of rule expirations. Treat the reports as asynchronous measurements, not an exact audit of delivered events. The [telemetry reference](telemetry.md) explains their scope and reset behavior.
