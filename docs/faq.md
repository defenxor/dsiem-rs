# Frequently asked questions

## Why use OSSIM-style correlation?

Dsiem was designed for teams using OSSIM rules who also wanted to use the Elastic stack for log ingestion and storage. It keeps a similar normalized event model and risk formula. The Rust implementation accepts IPv4 and IPv6 addresses and has three custom-data fields. See [normalized events](dsiem_plugin.md#normalized-event) and [differences from OSSIM](differences_from_ossim.md).

## What is included?

Dsiem-rs contains the correlation engine and a browser UI for investigating alarms and changing their status and tag. Log collection, parsing, searchable storage, and incident-response workflows use other components. The Docker examples include some of those components, but they are separate software.

The `dpluger`, `dtester`, and `nesd` tools are maintained in the [original Dsiem repository](https://github.com/defenxor/dsiem), not built by this Rust workspace.

## Why do alarms pass through Filebeat and Logstash?

The engine writes JSON-lines files so collection and storage transformations can be handled separately. Filebeat harvests those files, and Logstash applies the index routing and update rules before writing to Elasticsearch. Dsiem does not send alarms directly to Elasticsearch.

This separation does not guarantee delivery by itself. Retain Filebeat state, configure buffering and retries, and account for the sample's `tail_files: true` setting when starting with existing logs. See [event processing](event_processing.md).

## Can I use Dsiem without the Elastic stack?

The engine's input and output contracts allow another pipeline to send normalized JSON over HTTP and consume its alarm files. Preserve the alarm IDs, event IDs, and update semantics when implementing another storage path. The bundled browser UI and dashboards still require Elasticsearch and Kibana; they are not storage-independent.

## Which version should I deploy?

The source version is in [Cargo.toml](../Cargo.toml). Published artifacts are listed on the [releases page](https://github.com/defenxor/dsiem-rs/releases). The [release workflow](../.github/workflows/publish.yml) builds a container and Linux x86-64 archive when the version changes. Pin the artifact you have tested; the Compose examples use `latest` and are not evidence of a particular production deployment's current version.

## How do I evaluate it?

Use the [installation guide](installation.md) and the files in [deployments/docker](../deployments/docker). They include Suricata and a sample ping-flood directive. The [demo/get.sh](../demo/get.sh) helper can fetch demo files from the original Dsiem repository and patch their image references. Those deployment files are not bundled in this checkout. The helper removes other contents of its `demo/` directory and uses GNU-style `sed`, so inspect it before using it in a populated directory or on macOS.

## Where should analysts work?

Use Kibana to search events and monitor the alarm dashboard. Follow an alarm's `Dsiem Link` to inspect its correlation stages and linked events in the Dsiem UI, then update its status and tag. The UI can also delete an alarm and its links. It does not delete the underlying normalized events. See [web interfaces](web_interfaces.md).

## Why did an accepted event produce no alarm?

The HTTP response confirms frontend acceptance. The event still has to reach a backend and match a directive. A source-IP whitelist can exclude it, and an incomplete stage or zero risk can leave it without an alarm. Check the event type, source/destination conditions, stage counts, timeouts, and asset values. An address outside the configured assets has value zero. See [directive and alarm](directive_and_alarm.md).

## What should I check when processing falls behind?

Inspect watchdog reports and lag warnings, then compare filter allocation, active backlogs, and enrichment response times. Adding backend replicas helps only when directives are assigned appropriately; replicas do not automatically redistribute rules. See [managing performance](managing_performance.md).

## How do I access a remote deployment?

For the default lab, an SSH tunnel preserves the configured browser URLs:

```shell
ssh -N -L 8080:localhost:8080 -L 9200:localhost:9200 -L 5601:localhost:5601 user@your-server
```

Then open http://localhost:5601/ or http://localhost:8080/ui/ locally.

Alternatively, set `DSIEM_WEB_ESURL` and `DSIEM_WEB_KBNURL` in the frontend container to the server addresses reachable from the browser, then recreate the service with `docker compose up -d`. These variables write the UI's `esconfig.json`; they do not reconfigure network access or the Logstash destinations. Adjust the Kibana `Dsiem Link` URL if you change the UI port or path. Apply [access controls](security.md) before exposing those endpoints.

## Can another web server host the UI?

Yes. Serve the contents of `web/dist/` under `/ui/`, provide `/ui/assets/config/esconfig.json`, and serve or proxy `/config/dsiem_config.json`. The UI fetches both configuration files. It reads and updates alarm data directly in Elasticsearch.

The frontend normally generates `dsiem_config.json` from its status and tag options. If you host that file yourself, keep those choices consistent with backend defaults.

## How does Elasticsearch authentication work in the UI?

The [configuration reader](../web/src/services/config.rs) supports a username and password in the Elasticsearch URL and converts them into an HTTP Basic authorization header:

```json
{
  "elasticsearch": "https://USER:PASSWORD@elasticsearch.example/",
  "kibana": "https://kibana.example/"
}
```

Use a dedicated account with access to the alarm indices and the event indices needed for investigation. Anyone who can read this configuration can obtain the credentials. Cross-origin deployments also need Elasticsearch or its proxy to permit the UI's origin and request headers. See the [basic-auth example](../deployments/docker/docker-compose-basic-auth.yml) and [security notes](security.md).

## Can I enable a detection only during certain hours?

The supplied [Logstash filter script](../deployments/docker/conf/logstash/scripts/allow_within_timerange.rb) can control which normalized events reach Dsiem. Apply it before the HTTP output, while retaining the Elasticsearch event output as needed. For example:

```text
filter {
  if [@metadata][siem_data_type] == "normalizedEvent" {
    if [plugin_id] == 1001 and [plugin_sid] == 12345 {
      ruby {
        path => "/path/to/allow_within_timerange.rb"
        script_params => {
          "timestamp_field" => "timestamp"
          "time_from" => "23:00"
          "time_to" => "02:00"
        }
      }
    }
  }
}
```

The script returns no event outside the window, which drops that normalized event from all later outputs in the same pipeline. To keep all normalized events in Elasticsearch while limiting only correlation, apply the filter on a separate branch or pipeline dedicated to Dsiem. The script uses the Logstash process's local time zone; configure that zone explicitly if you require UTC. Its timestamp input must support conversion to epoch seconds, as with a Logstash date-filter timestamp.
