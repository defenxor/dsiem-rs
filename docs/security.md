# Security and access control

The Rust frontend has no built-in authentication or TLS termination. Its HTTP routes receive events, serve configuration files, and serve the web UI. Restrict access through the deployment network or an authenticated reverse proxy.

Configuration listing and download are enabled by default. `DSIEM_WRITEABLECONFIG=true` also enables HTTP upload and deletion at `/config/:filename`; it does not enable or disable filesystem writes. The frontend always writes `configs/dsiem_config.json` at startup, and the backend downloads configuration into its own `configs/` directory. Both directories therefore need appropriate write permissions. The backend also needs write access to `logs/`.

The browser reads `/config/dsiem_config.json` and `/ui/assets/config/esconfig.json`, then accesses Elasticsearch directly. It can read alarms and events, update alarm status and tags, and delete alarms and their event links. Protect Elasticsearch and grant the browser's account only the permissions needed for those operations. Restrict Kibana separately.

If an Elasticsearch username and password are placed in `esconfig.json`, anyone who can read that file can obtain them. Authenticating the page does not hide those credentials from an authorized browser user. The [basic-auth Compose example](../deployments/docker/docker-compose-basic-auth.yml) demonstrates integration and is configured for the built-in `elastic` account when used with a fresh cluster; it is not a least-privilege deployment template.

The [default Compose example](../deployments/docker/docker-compose.yml) disables Elasticsearch security and publishes application ports on the host. It is intended for evaluation on a restricted network.

The Dsiem processes need no packet-capture privileges. The separate Suricata container in the example has network capabilities because it captures traffic.

Input validation is implemented in [server.rs](../server/src/server.rs) and [server/validate.rs](../server/src/server/validate.rs). Validation is not access control: the server returns different HTTP errors for malformed input, invalid events, rate limits, and internal failures.

Report security-sensitive issues to devs@defenxor.com. The project's published GPG key lookup is [here](https://pgp.mit.edu/pks/lookup?search=devs%40defenxor.com).
