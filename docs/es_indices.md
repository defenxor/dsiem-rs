# Elasticsearch indices

The supplied [Logstash pipeline](../deployments/docker/conf/logstash/conf.d/80_siem.conf) and [Elasticsearch 7 templates](../deployments/docker/conf/logstash/index-template.d/es7) use these names:

| Physical index pattern | Content | Alias |
| --- | --- | --- |
| `siem_alarms-YYYY.MM.dd` | Alarm snapshots, including analyst status and tag | `siem_alarms`, `siem_alarms_id_lookup` |
| `siem_events-YYYY.MM.dd` | Normalized events | None in the supplied template |
| `siem_alarm_events-YYYY.MM.dd` | Alarm ID, event ID, and stage links | None in the supplied template |

The [web UI](../web/src/services/alarm.rs) searches alarms through `siem_alarms` and events through the `siem_events-*` and `siem_alarm_events-*` patterns. A single event can be linked to more than one alarm.

## Updating alarms across daily indices

Alarms can receive engine and analyst updates after their creation date. Before writing an engine update, Logstash searches `siem_alarms_id_lookup` for the alarm ID and reads its `perm_index` field. If found, it updates that original index. Otherwise, it writes to today's alarm index and records that index in `perm_index`.

The update script ignores a lower incoming risk, or an older `updated_time` when risk is equal. It updates correlation data while preserving an existing alarm's analyst-managed `status` and `tag`.

The lookup alias must cover indices containing alarms that may still receive updates. Removing an index from that alias, or a failed lookup, can cause an update to be written into a new daily index instead. The pipeline does not provide a global uniqueness guarantee across indices.

Normalized events and alarm-event links are append-oriented records. The supplied event output uses `event_id` as the Elasticsearch document ID; alarm-event links do not set an explicit document ID.

## Optional direct Filebeat output

The [filebeat-es module](../deployments/docker/conf/filebeat-es/module/dsiem/_meta/docs.asciidoc) is a separate alarm-only mapping. It does not implement the aliases, linked-event storage, or analyst-field preservation described above, and is not enabled by the supplied Compose files.
