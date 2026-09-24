# Directive and Alarm

A directive describes how incoming [normalized events](dsiem_plugin.md#normalized-event) are correlated into an alarm. It contains a sequence of rules with occurrence counts, matching conditions, and timeouts.

## About directive rules

`PluginRule` matches `plugin_id` and `plugin_sid`. Use it when detection depends on specific event types from a known source.

`TaxonomyRule` matches `product`, `category`, and optionally `subcategory`. It lets different sources participate in a rule when their normalized events use the same classification scheme. Maintaining that shared scheme is part of configuring the source parsers.

Both rule types can also constrain addresses, ports, protocol, and custom fields. For example, a directive can track an IDS alert followed by a firewall event showing allowed traffic. It needs those matching events; the absence of a blocked-traffic event alone does not satisfy a stage.

## Rule format

A directive file contains a top-level `directives` array. Each directive needs `id`, `name`, `priority`, `kingdom`, `category`, and `rules`. Use a unique ID, nonempty names/classifications, and priority from 1 to 5. `disabled` and `all_rules_always_active` default to `false`.

Define at least two rules, with consecutive stages starting at 1, and set stage 1's `occurrence` to 1. References depend on those stage positions. Startup rejects invalid enabled directives instead of repairing or skipping them. Disabled directives are skipped; the backend needs at least one enabled directive.

| Field | Required | Meaning |
| --- | --- | --- |
| `name` | Yes | Rule name; the field must be present |
| `type` | Yes | `PluginRule` or `TaxonomyRule` |
| `stage` | Yes | Stage number, starting at 1 |
| `occurrence` | Yes | Positive count of matching event IDs; stage 1 must use 1 |
| `from`, `to` | Yes | Source/destination address conditions |
| `port_from`, `port_to` | Yes | Source/destination port conditions; use `ANY` to ignore |
| `protocol` | Yes | Exact protocol string, `ANY`, empty string, or a stage reference |
| `reliability` | Yes | Integer from 0 to 10, used when the stage completes |
| `timeout` | Yes | Nonnegative integer in seconds; there is no deserialization default |
| `plugin_id` | For `PluginRule` | Positive plugin ID |
| `plugin_sid` | For `PluginRule` | Nonempty array of positive event-type IDs |
| `product` | For `TaxonomyRule` | Nonempty array of product strings |
| `category` | For `TaxonomyRule` | Nonempty category string |
| `subcategory` | No | Array of strings for a taxonomy rule; empty or containing `ANY` means unrestricted |
| `custom_data1`, `custom_data2`, `custom_data3` | No | Custom-field conditions; omitted, empty, or `ANY` means unrestricted |
| `sticky_different` | No | Require a new value in the selected field while counting matches |

Address conditions support `ANY`, `HOME_NET`, `!HOME_NET`, IP addresses, CIDRs, comma-separated entries, and `!` negation. `HOME_NET` is built from non-whitelisted entries in `assets_*.json`. Both IPv4 and IPv6 are supported. Port conditions support `ANY`, ports from 1 to 65535, comma-separated entries, negation, and references. Empty or missing port conditions are invalid.

The supported rule-level `sticky_different` selectors are `SRC_IP`, `DST_IP`, `SRC_PORT`, `DST_PORT`, `PLUGIN_SID`, and `CUSTOM_DATA1` through `CUSTOM_DATA3`.

### Referencing a previous stage

Use `:1`, `:2`, and so on to match the corresponding field of the first event in a previous stage. For example, `"from": ":1"` requires the same source address as the first event in stage 1. It does not match against every address seen during that stage.

References are supported in `from`, `to`, `port_from`, `port_to`, `protocol`, and the three `custom_data` fields. Use only earlier stages. Address and port reference validation accepts `:1` through `:99` within the directive's highest stage; it does not verify every ordering constraint. Write stages consecutively and keep references backward even if a malformed directive passes startup validation.

See [directive loading and validation](../server/src/directive.rs) and [rule deserialization and matching](../server/src/rule.rs) for the implementation.

## Directive and Rules Processing

The following is an example of a dsiem directive that has several `PluginRule`.

```json
{
  "name": "Ping Flood from SRC_IP",
  "kingdom": "Reconnaissance & Probing",
  "category": "Misc Activity",
  "id": 1,
  "priority": 3,
  "rules" : [
    { "name": "ICMP Ping", "type": "PluginRule", "stage": 1, "plugin_id": 1001,
      "plugin_sid": [ 2100384 ], "occurrence": 1, "from": "HOME_NET", "to": "ANY",
      "port_from": "ANY", "port_to": "ANY", "protocol": "ICMP",
      "reliability": 1, "timeout": 0
    },
    { "name": "ICMP Ping", "type": "PluginRule", "stage": 2, "plugin_id": 1001,
      "plugin_sid": [ 2100384 ], "occurrence": 5, "from": ":1", "to": "ANY",
      "port_from": "ANY", "port_to": "ANY", "protocol": "ICMP",
      "reliability": 5, "timeout": 600
    },
    { "name": "ICMP Ping", "type": "PluginRule", "stage": 3, "plugin_id": 1001,
      "plugin_sid": [ 2100384 ], "occurrence": 500, "from": ":1", "to": "ANY",
      "port_from": "ANY", "port_to": "ANY", "protocol": "ICMP",
      "reliability": 10, "timeout": 3600
    }
  ]
}
```
Notice that the directive `Ping Flood from SRC_IP` above has 3 `rules`, each having a `stage` from 1 to 3 and different value for `reliability` and `timeout` keys.

When an incoming event matches a directive's stage 1 rule condition, dsiem will create a backlog object associated with that directive to track the progress of this potential alarm.

Dsiem counts matching event IDs for the current stage. Once the count reaches `occurrence`, it calculates risk and advances to the next stage. On the final stage, it writes the last alarm update and removes the backlog from memory.

A new stage initially uses the previous stage's completion event timestamp as its start time. Its first matching event resets that start time to its own timestamp. The expiration check runs every 10 seconds and compares wall-clock time with:

```text
stage start time + timeout + min-alarm-lifetime (converted to seconds)
```

`timeout=0` does not disable expiration. `--min-alarm-lifetime` adds time to this deadline; it does not delay removal after the final stage completes. When a backlog expires, Dsiem marks the current rule `timeout`, writes an alarm update if risk is nonzero, and removes the backlog. Existing alarm documents remain available for investigation.

With `all_rules_always_active=true`, an event that fails the current stage can still be attached to a matching earlier stage. This does not advance the current stage or recalculate risk.

## Triggering Alarm

Dsiem calculates risk when a stage reaches its required occurrence count. It writes an alarm when the resulting integer is greater than zero:

```text
risk = (reliability × priority × asset value) / 25
```

The Rust implementation uses integer division, so it discards the fractional part. Reliability ranges from 0 to 10 and directive priority from 1 to 5. Configure asset values from 1 to 5 for the intended 0-to-10 scoring scale. The asset loader rejects zero but does not enforce an upper bound of 5.

For each involved source and destination address, Dsiem takes the highest value among matching asset entries, then uses the highest value across those addresses. An address with no matching asset has value 0, not a default value of 2. If none of the involved addresses match an asset, risk remains zero.

The default classifications are:

- Low: 1 or 2.
- Medium: 3 through 6.
- High: above 6, up to 10 when using the intended asset scale.

`--med_risk_min` and `--med_risk_max` control the Medium boundaries. An alarm can be emitted before the final stage and updated as later stages finish. Threat-intelligence and vulnerability matches add context without changing risk.

### Example directive-to-alarm processing

Use the three-stage directive above and an asset value of 4 for `10.0.0.0/8`. Assume all events match the configured plugin, SID, and protocol and arrive within the stage timeouts.

1. An event from `10.0.0.1` starts backlog A. Stage 1 completes, but `(1 × 3 × 4) / 25` becomes integer `0`, so no alarm is written.
2. Five more matching events from `10.0.0.1` complete stage 2. Risk becomes `(5 × 3 × 4) / 25 = 2`, producing a Low alarm. Stage 3 starts.
3. Ten more matching events give stage 3 a count of 10 out of 500. The alarm remains Low; the stage is not complete.
4. Another 490 matching events complete stage 3. Risk becomes `(10 × 3 × 4) / 25 = 4`. Dsiem writes a Medium alarm update and removes backlog A from memory.

An event from `10.0.0.2` can start a separate backlog because stage 2 of backlog A refers to stage 1's source address. An unfinished backlog expires according to its current stage's deadline.

This example is separate from the [shipped test directive](../configs/directives_dsiem-backend-0_testing1.json), which uses stage-2 occurrence 3 and reliability 6, followed by stage-3 occurrence 10,000.

The scoring and stage transitions are implemented in [backlog/mod.rs](../server/src/backlog/mod.rs).

## Creating a Dsiem Directive

Basic Dsiem directives can be created automatically by parsing TSV files produced by `dpluger` tool during [Dsiem plugin creation process](dsiem_plugin.md#example-2-sid-based-plugin-with-generated-plugin-sid). These directives are basic because they're only looking for events that have identical `PluginID` and `PluginSID` combination, and identical source and destination IP address pair.

For example, given a `sangfor_plugin-sids.tsv` file with the following content:
```tsv
plugin      id      sid     title
sangforIPS  20001   1       Botnet
sangforIPS  20001   2       Abnormal Connection
```

we can use the following `dpluger` command:
```console
./dpluger directive -i 3001 -f sangfor_plugin-sids.tsv
```
The external tool can generate a `directives_dsiem.json` file like the example below. Rename it to match the backend assignment, such as `directives_dsiem-backend-0_generated.json`, before placing it in the frontend configuration directory. Check `dpluger directive --help` for the version you installed:
```json
{
  "directives": [
    {
      "id": 3001,
      "name": "Botnet (SRC_IP to DST_IP)",
      "priority": 3,
      "kingdom": "Environmental Awareness",
      "category": "Misc Activity",
      "rules": [
        {
          "name": "Botnet",
          "stage": 1,
          "plugin_id": 20001,
          "plugin_sid": [
            1
          ],
          "occurrence": 1,
          "from": "ANY",
          "to": "ANY",
          "type": "PluginRule",
          "port_from": "ANY",
          "port_to": "ANY",
          "protocol": "TCP/IP",
          "reliability": 1,
          "timeout": 0
        },
        {
          "name": "Botnet",
          "stage": 2,
          "plugin_id": 20001,
          "plugin_sid": [
            1
          ],
          "occurrence": 10,
          "from": ":1",
          "to": ":1",
          "type": "PluginRule",
          "port_from": "ANY",
          "port_to": "ANY",
          "protocol": "TCP/IP",
          "reliability": 5,
          "timeout": 3600
        },
        {
          "name": "Botnet",
          "stage": 3,
          "plugin_id": 20001,
          "plugin_sid": [
            1
          ],
          "occurrence": 10000,
          "from": ":1",
          "to": ":1",
          "type": "PluginRule",
          "port_from": "ANY",
          "port_to": "ANY",
          "protocol": "TCP/IP",
          "reliability": 10,
          "timeout": 21600
        }
      ]
    },
    {
      "id": 3002,
      "name": "Abnormal Connection (SRC_IP to DST_IP)",
      "priority": 3,
      "kingdom": "Environmental Awareness",
      "category": "Misc Activity",
      "rules": [
        {
          "name": "Abnormal Connection",
          "stage": 1,
          "plugin_id": 20001,
          "plugin_sid": [
            2
          ],
          "occurrence": 1,
          "from": "ANY",
          "to": "ANY",
          "type": "PluginRule",
          "port_from": "ANY",
          "port_to": "ANY",
          "protocol": "TCP/IP",
          "reliability": 1,
          "timeout": 0
        },
        {
          "name": "Abnormal Connection",
          "stage": 2,
          "plugin_id": 20001,
          "plugin_sid": [
            2
          ],
          "occurrence": 10,
          "from": ":1",
          "to": ":1",
          "type": "PluginRule",
          "port_from": "ANY",
          "port_to": "ANY",
          "protocol": "TCP/IP",
          "reliability": 5,
          "timeout": 3600
        },
        {
          "name": "Abnormal Connection",
          "stage": 3,
          "plugin_id": 20001,
          "plugin_sid": [
            2
          ],
          "occurrence": 10000,
          "from": ":1",
          "to": ":1",
          "type": "PluginRule",
          "port_from": "ANY",
          "port_to": "ANY",
          "protocol": "TCP/IP",
          "reliability": 10,
          "timeout": 21600
        }
      ]
    }
  ]
}
```
The generated directives above have the following characteristics:
- Directive IDs are assigned sequentially starting with the number provided by the `-i` parameter to `dpluger`. This parameter is required to prevent conflicting IDs with directives already defined in other files.
- Each directive has 3 correlation rule stages:
  - stage 1: match a single event that has similar `PluginID` and `PluginSID` combination as specified by each row of the TSV file.
  - stage 2: has similar condition with stage 1, with an added requirement for the events to also match stage 1 source and destination IP addresses. This stage is set to match up to 10 events within 3,600 seconds (1 hour).
  - stage 3: has similar condition with stage 2, but is setup to match up to 10,000 events within 6 hour.
- The example priority is 3, and the stage reliabilities are 1, 5, and 10. With an explicitly configured asset value of 2, stage 2 produces integer risk 1. Addresses outside the asset configuration have value 0.
- The generated `protocol: "TCP/IP"` condition requires that exact event protocol. Change it to the source's actual protocol or `ANY`; `TCP/IP` is not a wildcard.
