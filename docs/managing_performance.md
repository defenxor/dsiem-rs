# Managing Performance

Dsiem is designed to scale horizontally, which means we can add more nodes and distribute correlation rule directives among them to cope with increasing demands.

In practice however, hardware and network resources are often limited, and we will have to work with what's available at hand.

This page gives several suggestions on how to deploy Dsiem with performance consideration in mind. In addition, tips on how to detect performance issue are also given at [the end of this page](#Detecting-performance-issue).

## Evaluate the most likely performance bottleneck

The first thing to know is that for each incoming event, Dsiem will quickly compare several key fields (like `Plugin ID` and `Plugin SID`) against all directives to determine if there's a match. Only matching events will be sent afterwards to the associated directives for further processing. Because this initial quick comparison is done to _all_ events against _all_ directives, it becomes a main spot for potential performance bottleneck and should therefore be allocated with enough CPU resources.

In our tests, a single CPU thread was able to perform around 17 million quick filtering checks per second, so the rate of incoming events/sec times the number of directives should not exceed that number.

$$ {17,000,000} × {n_{cpu}} = {n_{eps}} × {n_{directive}} $$

For example suppose you dedicate 1 CPU thread to perform quick checks on a node that is hosting 10,000 directives. We can calculate the maximum events/sec rate before the system may start lagging behind:

$$ {n_{eps}} = \frac{{17,000,000} × 1}{10,000} = 1,700$$

> [!NOTE]
> By default, Dsiem uses the above calculation to determine the number of CPU threads to allocate for quick checks. 
> You can override this by specifying `DSIEM_FILTER_THREADS` environment variable or `--filter-threads` startup parameter.

If that rate limit is persistently exceeded, the queue will start filling up and eventually events will be dropped. In such cases, first consider increasing the number of threads allocated so that directives are processed in parallel. If that's not feasible, then consider applying one of, or a combination of, reconfigurations outlined below.

## Selectively ingest logs from Logstash

It makes no sense to send a log to Dsiem if you don't have correlation rules for it.

You can avoid sending unnecessary logs by reconfiguring the Logstash filter that generates the normalized events. Similar effect can also be achieved by supplying an appropriate filter in `dplugin_config.json` before running `dpluger run` command to create the Logstash plugin.

## Distribute directives to multiple nodes located on different hardware

This is as straightforward horizontal scaling solution. By distributing the directives to multiple nodes each running on a different hardware, the system will have more processing power to execute the same workload in parallel.

Note that for Dsiem in this repo, distributing directives to multiple dsiem backend nodes running on the same hardware most likely _will not_ achieve higher performance compared to just hosting all of those directives in a single node. A single backend node is capable of utilizing all of the CPU cores assigned to it, so multiple nodes will only introduce extra overhead without significant gain.

## Prioritise directives and allocate resources accordingly

Directives are not created equal. Directives that detect more severe consequences should be given higher priority and should receive more allocation compared to other directives.

You can treat directives differently by using a separate set of nodes (both frontend and backend) for each class of directives, and defining a separate overload coping strategy for each of them.

Dsiem offers two such strategies to select from:

1. Use a fixed length queue and discard new events when that queue is full

   The advantages of this strategy are:
   - Events that *do* get processed will have a recent timestamp.
   - Backend nodes will have a relatively constant and predictable resource usage.
   - NATS, Logstash, and frontend nodes do not have to adapt to backend nodes condition.

   The obvious (and rather severe) disadvantage of this is Dsiem may skip processing events from time to time.

> [!NOTE]
> Use this strategy by setting `max_queue` to a number higher than 0, and `max_delay` to 0.
> 
> The fixed queue length then will be set to `max_queue`, and `max_delay` = 0 will prevent frontend from throttling incoming events.


2. Use an unbounded queue and auto-adjust frontend ingestion rate (events/sec) to apply back-pressure to Logstash

   In this case whenever Dsiem backend nodes detect an event that has a timestamp older than the configured threshold, they will instruct frontends to reduce the rate of incoming events from Logstash. Frontends will gradually increase its ingestion rate again once the backends no longer report overload condition.

   Advantage of this strategy is that eventually all events will be processed in order.

   The disadvantages are:
    - There could be processing delays from time to time.
    - The processing delays may never go away if the log sources never reduce their output rate.
    - Sustained reduction of delivery rate from Logstash to frontends will cause Logstash to overflow its queue capacity, and depending on how it's configured, Logstash may end up stop receiving incoming events from its input. Using Logstash persistent queue backed by a large amount of storage space will not help either — in fact that may only worsen the processing delay issue.

> [!NOTE]
> Use this strategy by setting `max_queue` to 0, and `max_delay` to a number higher than 0. The queue length will then be unbounded, and `max_delay` (seconds) will be used by backend to detect processing delay and report this condition to frontend, which will then apply back-pressure to Logstash.
> 
> _Processing delay_ occurs when the duration between the time that _an event was received by frontend_ to the time when _that event is processed by a directive_, is greater than `max_delay`.

Now, for instance suppose that in a limited resource environment, you have 100 critical directives and 1000 lower priority directives both evaluating the same sources of logs. You want the critical directives to be applied to all events at all times, and to have a maximum processing delays of 5 minutes. In exchange for that, you're willing to let the lower priority directives occasionally skip events, as long as the alarms that they do manage to produce are based on recent enough events, which will make them at least relevant and still actionable.

Given that scenario, you can use the following strategy to make the best out of the situation:

- Use unbounded queue and Dsiem EPS rate auto-adjustment (with threshold set to 5 minutes delay) on a set of nodes that host the 100 critical directives. Make sure that the nodes have enough hardware resources allocated to cope with normal ingestion rate, so that the auto-adjustment will only be triggered sparingly during a temporary spike and will not last for long. 
At Logstash end, use persistent queue on the pipeline with enough capacity to prevent it from blocking its input during reduced output rate to Dsiem frontend. This last bit isn't necessary if the input is Filebeat, or similar producer that doesn't discard events when they can't send to Logstash.

- Use fixed length queue on a set of nodes that host the lower priority directives. They can run on the hardware that aren't being used by the nodes hosting critical directives.

## Shield the main Logstash ingestion pipeline

For production use, it's important to make sure that any Dsiem performance issues or downtime will not affect the main Logstash ingestion pipeline to Elasticsearch.

This can be implemented using Logstash [pipeline-to-pipeline](https://www.elastic.co/guide/en/logstash/current/pipeline-to-pipeline.html) feature or by running a cascade of Logstash instances configured in a certain way. To assist in this, `dpluger run` has a `--usePipeline` flag that will create plugins in a format that is more suitable for multiple pipeline configuration.

## Detecting performance issue

Dsiem regularly prints out information that can be used to detect performance-related issues.

The following shows an example of a node with a fixed length queue having problem keeping up with the inbound ingestion rate:

```shell
docker logs dsiem-backend -f --since=5m | jq --unbuffered -c '.fields' | grep -E '(watchdog|lagged)'

{"message":"watchdog report","eps":1636.36,"queue_length":8733,"avg_proc_time_ms":0.035,"ttl_directives":5001,"active_directives":70,"backlogs":284,"timedout_backlogs":0}
{"message":"watchdog report","eps":1571.43,"queue_length":18530,"avg_proc_time_ms":0.037,"ttl_directives":5001,"active_directives":70,"backlogs":290,"timedout_backlogs":0}
{"message":"watchdog report","eps":1548.39,"queue_length":28382,"avg_proc_time_ms":0.039,"ttl_directives":5001,"active_directives":70,"backlogs":295,"timedout_backlogs":0}
{"message":"filtering lagged and skipped 2 events"}
{"message":"filtering lagged and skipped 1 events"}
{"message":"filtering lagged and skipped 1 events"}
{"message":"filtering lagged and skipped 2 events"}

```

Those log lines show the following:
- The queue length keeps rising until it's full, and events are skipped (not processed). This is the **_most important_** metric to evaluate Dsiem backend node performance issues.
- Average processing time stays low around 0.03 ms for the configured `max_eps` parameter of 1000 events/sec (or 1ms max. processing time per event). This parameter is measuring backlog processing time, which for Dsiem in this repo, is _no longer the likely location for bottlenecks_.
- The system has > 280 active backlogs, all created from just 70 of the 5001 directives defined.

Based on the above we can try to relieve the performance bottleneck by:
- Increasing the number of filtering threads;
- Moving the rarely used directives to other nodes running on a different hardware.

Both options essentially split the directives processing to more CPU threads, thereby preventing the queue from constantly being filled to its maximum capacity.

As a comparison, here's an example log output from a node that isn't experiencing performance problem:

```shell
docker logs dsiem-backend -f --since=5m | jq --unbuffered -c '.fields' | grep -E '(watchdog|lagged)'

{"message":"watchdog report","eps":1615.38,"queue_length":5,"avg_proc_time_ms":0.023,"ttl_directives":5001,"active_directives":70,"backlogs":552,"timedout_backlogs":0}
{"message":"watchdog report","eps":1565.22,"queue_length":11,"avg_proc_time_ms":0.025,"ttl_directives":5001,"active_directives":70,"backlogs":580,"timedout_backlogs":0}
{"message":"watchdog report","eps":1545.45,"queue_length":1,"avg_proc_time_ms":0.028,"ttl_directives":5001,"active_directives":70,"backlogs":601,"timedout_backlogs":0}
{"message":"watchdog report","eps":1535.07,"queue_length":1,"avg_proc_time_ms":0.03,"ttl_directives":5001,"active_directives":70,"backlogs":615,"timedout_backlogs":0}
{"message":"watchdog report","eps":1531.58,"queue_length":0,"avg_proc_time_ms":0.031,"ttl_directives":5001,"active_directives":70,"backlogs":621,"timedout_backlogs":0}
```

Those log lines show that:
- The queue is almost never used at all. Single event processing time is around 0.02-0.03 ms, still way faster than the configured limit of 1ms (or `max_eps` parameter of 1k/sec).
- The node is tracking >500 active backlogs created from 70 directives (out of the total 5001 directives defined), and that doesn't negatively affect its performance.

So for this particular node, we can try to increase its utilisation by moving more directives to it, or by increasing its incoming event ingestion rate.
