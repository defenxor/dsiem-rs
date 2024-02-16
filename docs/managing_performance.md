# Managing Performance

Dsiem is designed to scale horizontally, which means we can add more nodes and distribute correlation rule directives among them to cope with increasing demands.

In practice however, hardware and network resources are often limited, and we will have to work with what's available at hand.

This page gives several suggestions on how to deploy Dsiem with performance consideration in mind. In addition, tips on how to detect performance issue are also given at [the end of this page](#Detecting-performance-issue).

## Selectively ingest logs from Logstash

It makes no sense to send a log to Dsiem if you don't have correlation rules for it.

You can avoid sending unnecessary logs by reconfiguring the Logstash filter that generates the normalized events. Similar effect can also be achieved by supplying an appropriate filter in `dplugin_config.json` before running `dpluger run` command to create the Logstash plugin.

## Distribute directives to multiple nodes (and hardware whenever possible)

The typical Logstash ingestion pipeline(s) will always process events faster than Dsiem that has to correlate those events against X number of directives. The more directives you have on a single node, the more pronounced this effect will be. 

For instance, given the following backend nodes:
- backend-A, 1000 directives defined, 10 active backlogs in memory 
- backend-B, 100 directives defined, 1000 active backlogs in memory

Backend-A will have a harder time keeping up with the rate of incoming events compared to backend-B, even though most of its 1000 directives never actually match any of those events (hence its low number of active backlogs).

The above is true because in order to process things concurrently as much as possible, Dsiem copies each incoming event to an array of backlog managers, each of whom responsible for a single directive defined in the configuration files. So if you have 2000 directives defined, at runtime you will have 2000 backlog managers all waiting for the next event to process.

Those backlog managers will then have to compete for the system's limited CPU cores when processing incoming events. In a system handling 2000 events/sec, individual backlog managers will have to process *each* event in less than 500μs to avoid introducing delays. Having fewer directives reduces competition for CPU time, and therefore allows each directive to complete its processing within the time duration limit.

## Prioritise directives and allocate resources accordingly

Directives are not created equal. Directives that detect more severe consequences should be given higher priority and should receive more allocation compared to other directives.

You can treat directives differently by using a separate set of nodes (both frontend and backend) for each class of directives, and defining a separate overload coping strategy for each of them.

Dsiem offers two such strategies to select from:

1. Use a fixed length queue and discard new events when that queue is full

   The advantages of this strategy are:
   - Events that *do* get processed will have a recent timestamp.
   - Backend nodes will have a relatively constant and predictable resource usage.
   - NATS, Logstash, and frontend nodes do not have to adapt to backend nodes condition.

   The obvious (and rather severe) disadvantage of this is Dsiem will skip processing events from time to time.

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
> Use this strategy by setting `max_queue` to 0, and `max_delay` to a number higher than 0. The queue length will then be unbounded, and `max_delay` >(seconds) will be used by backend to detect processing delay and report this condition to frontend, which will then apply back-pressure to Logstash.
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

{"message":"watchdog report","eps":980.02,"queue_length":49231,"avg_proc_time_ms":2.145,"ttl_directives":1283,"active_directives":30,"backlogs":425}
{"message":"watchdog report","eps":985.11,"queue_length":49973,"avg_proc_time_ms":0.116,"ttl_directives":1283,"active_directives":30,"backlogs":430}
{"message":"avg. processing time maybe too long to sustain the target 1000 event/sec (or 1 ms/event)","avg_proc_time_ms":2.25}
{"message":"avg. processing time maybe too long to sustain the target 1000 event/sec (or 1 ms/event)","avg_proc_time_ms":3.11}
{"message":"event receiver lagged and skipped 2207 events","directive_id":1251}
```

Those log lines show the following:
- There are around 49k events constantly in queue, and 2207 events have been skipped by directive 1251.
- Average processing time fluctuates between 0.1 to 3 ms, and that upper range is too long for the configured `max_eps` parameter of 1000 events/sec (or 1ms max. processing time per event). This long processing time is what causing the queue to fill up and never had a chance to drain.
- The system has > 400 active backlogs, all created from just 30 of the 1283 directives defined.

Based on the above we can try to relieve the performance bottleneck by moving the rarely used directives to other nodes running on a different hardware. This change will reduce the average processing time and thereby preventing the queue from constantly being filled to its maximum capacity.

As a comparison, here's an example log output from a node that isn't experiencing performance problem:

```shell
docker logs dsiem-backend -f --since=5m | jq --unbuffered -c '.fields' | grep -E '(watchdog|lagged)'

{"message":"watchdog report","eps":750.02,"queue_length":0,"avg_proc_time_ms":0.21,"ttl_directives":77,"active_directives":9,"backlogs":1425}
{"message":"watchdog report","eps":794.11,"queue_length":0,"avg_proc_time_ms":0.10,"ttl_directives":77,"active_directives":9,"backlogs":1427}
{"message":"watchdog report","eps":771.45,"queue_length":0,"avg_proc_time_ms":0.07,"ttl_directives":77,"active_directives":9,"backlogs":1427}
```

Those log lines show that:
- The queue is never used at all. Single event processing time is around 0.1-0.2ms, still way faster than the configured limit of 1ms (or `max_eps` parameter of 1k/sec).
- The node is tracking almost 1500 active backlogs created from 9 directives (out of the total 77 directives defined), and that doesn't negatively affect its performance.

So for this particular node, we can try to increase its utilisation by moving more directives to it, or by increasing its incoming event ingestion rate.
