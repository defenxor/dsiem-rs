# Installation

Dsiem-rs runs as separate frontend and backend processes connected through NATS. The supplied deployment also uses Elasticsearch, Logstash, Filebeat, and Kibana. Suricata supplies sample events.

## Using Docker Compose

The [default Compose file](../deployments/docker/docker-compose.yml) is a lab setup. It pins Elastic components to 7.11.0 and NATS to `1.3.0-linux`, uses `defenxor/dsiem-rs:latest`, and disables Elasticsearch authentication. These versions describe the example, not a compatibility guarantee for other releases.

The Suricata example uses host networking and Linux network capabilities to capture a host interface. Run it on a suitable Linux Docker host. Do not assume that a macOS or Windows host interface is visible inside Docker's Linux VM.

From a checkout of this repository:

```shell
cd deployments/docker
export PROMISC_INTERFACE=eth0
sudo find conf/filebeat conf/filebeat-es -name '*.yml' -exec chown root {} +
docker compose pull
docker compose up -d
```

Replace `eth0` with the interface that Suricata should monitor. The ownership step prepares the mounted Filebeat configuration files for its permission checks. Use `docker-compose` instead of `docker compose` if that is the command provided by your installation.

The alternative `docker-compose-basic-auth.yml` also requires `ES_USERNAME` and `ES_PASSWORD`. On a fresh example cluster, use `elastic` for `ES_USERNAME`; the Compose file sets that built-in account's password but does not create an arbitrary named user. The telemetry alternative is `docker-compose-telemetry.yml`. Select either with `docker compose -f <filename> ...` from the same directory.

The services expose:

| Service | Local URL |
| --- | --- |
| Dsiem UI | http://localhost:8080/ui/ |
| Elasticsearch | http://localhost:9200/ |
| Kibana | http://localhost:5601/ |

These are browser URLs. If the browser runs on another machine, either tunnel these ports over SSH or set `DSIEM_WEB_ESURL` and `DSIEM_WEB_KBNURL` to addresses it can reach. See [remote access](faq.md#how-do-i-access-a-remote-deployment).

The container launcher uses `DSIEM_MODE=cluster-frontend` or `cluster-backend` to choose the executable and requires `DSIEM_NODE`. An empty frontend `/dsiem/configs` directory is seeded from `/dsiem/configs-dist`. Backends download their configuration from the frontend at startup.

The sample intel and vulnerability sources are enabled but their lookup services are not included. Disable them or provide reachable endpoints as described in [lookup plugins](ti_vuln_plugins.md).

The default example mounts a volume at backend `/dsiem/logs`, but explicitly sets `DSIEM_RELOAD_BACKLOGS=false`. To preserve active detections across graceful restarts, enable that setting and retain the logs volume. See [restart recovery](../README.md#saving-and-reloading-backlogs-on-restart).

### Triggering a test alarm

The sample [directive](../configs/directives_dsiem-backend-0_testing1.json) expects Suricata ICMP events with plugin ID `1001` and SID `2100384`. Stage 1 starts tracking; three further matching events from the same source complete stage 2.

From another host, continuously ping the address on the monitored interface. The source must match a non-whitelisted `HOME_NET` entry in [assets_testing.json](../configs/assets_testing.json). Adjust the asset networks if your test network differs. With the supplied asset value 5, stage 2 produces risk 3 (Medium).

Confirm that Suricata emits the expected signature, Logstash writes `siem_events-*`, and the backend writes alarms. The alarm pipeline stores documents in daily `siem_alarms-*` indices exposed through the `siem_alarms` alias. A successful HTTP submission alone does not confirm that an alarm was generated.

### Importing the Kibana dashboard

After test events and an alarm have created the indices, run this from the repository root:

```shell
./scripts/kbndashboard-import.sh localhost ./deployments/kibana/dashboard-siem.json
```

Keep `idxpattern-siem_alarm_events.json` beside the dashboard file so the script can also import that index pattern. For the authenticated example, set `ES_USERNAME` and `ES_PASSWORD` before running the script.

The import script uses the bundled Kibana dashboard API format and also checks Elasticsearch at `localhost:9200`, even when another Kibana host is supplied. Run it where that endpoint is available, or adapt the script for your deployment. Do not assume the bundled dashboard works unchanged with another major Elastic version.

## Using an existing logging stack

1. Obtain the Linux x86-64 release archive from the [releases page](https://github.com/defenxor/dsiem-rs/releases), or [build the binaries and UI](building.md).
2. Install and start NATS where both Dsiem processes can reach it.
3. Place the frontend and backend in separate installation directories, with `configs/` beside each executable. Put the browser build in the frontend's `web/dist/` directory. Give the frontend write access to its configuration directory and the backend write access to its configuration and logs directories.
4. Put assets, directives, and optional enrichment configuration in the frontend directory. Name directive files for their backend, such as `directives_dsiem-backend-0_custom.json`. Keep the backend's local directory free of stale directives from previous assignments.
5. Adapt the [Logstash configuration](../deployments/docker/conf/logstash) to your sources and Elasticsearch deployment. It uses the UUID and prune filters, the Elasticsearch lookup filter, and HTTP/Elasticsearch outputs; ensure those plugins are available.
6. Configure [Filebeat](../deployments/docker/conf/filebeat/filebeat.yml) to harvest the backend's `logs/siem_alarms.json` and `logs/siem_alarm_events.json` and send them to Logstash. Preserve Filebeat's registry data. The sample uses `tail_files: true`, so a newly discovered file starts at its end; account for that if importing pre-existing output.
7. Configure browser access and import the dashboard as described above.

The release archive contains a top-level `dsiem/` directory. For example, extracting it under `/var` places the binaries under `/var/dsiem/`, not directly under whichever directory you make first. Keep each process's `configs/`, `logs/`, and `web/dist/` relative to its executable; changing the working directory does not change those paths.

For a frontend under `/var/dsiem-frontend` and a backend under `/var/dsiem-backend`, start the processes in separate terminals after preparing those directories:

```shell
/var/dsiem-frontend/dsiem-frontend serve \
  --node dsiem-frontend-0 \
  --msq nats://localhost:4222
```

```shell
/var/dsiem-backend/dsiem-backend serve \
  --node dsiem-backend-0 \
  --frontend http://localhost:8080 \
  --msq nats://localhost:4222
```

`DSIEM_FRONTEND` is an HTTP configuration URL. `DSIEM_MSQ` is the NATS URL. Use the same executable paths and arguments in your service manager, with a writable installation layout and enough shutdown time to save backlogs. The backend requires the frontend configuration endpoint at startup; configure restart behavior if services start out of order.

In the frontend's `web/dist/assets/config/esconfig.json`, set URLs reachable from the browser:

```json
{
  "elasticsearch": "http://elasticsearch.example:9200/",
  "kibana": "http://kibana.example:5601/"
}
```

A source-built UI does not create this runtime configuration file for you. The frontend creates `/config/dsiem_config.json` from its status/tag settings at startup. If another web server hosts the UI, it must also serve or proxy that route. See [access control](security.md) before configuring credentials or exposing the services.

## Stopping and removing the lab

From `deployments/docker`, stop and remove the containers while retaining named volumes:

```shell
docker compose down
```

Only add `-v` if you intend to delete the named volumes, including Elasticsearch data, Filebeat state, and Dsiem logs. For a manual installation, stop its services before removing installation directories or retained data.
