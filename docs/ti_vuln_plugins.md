# Threat intelligence and vulnerability lookup plugins

Lookup plugins add context to alarms. They do not change the risk score. The Rust backend currently includes Wise for IP intelligence and Nesd for vulnerability lookup by IP/port pair.

Intel checks skip non-global addresses unless `DSIEM_INTELPRIVATEIP=true` or `--intel_private_ip` is set. Vulnerability checks include private addresses. Lookup failures are logged and do not prevent the alarm update from being written, though waiting for a lookup can delay that update.

## Configuration

Place `intel_*.json` and `vuln_*.json` files in the frontend's configuration directory. Backends download them at startup. A source is enabled only when its `enabled` field is true and its `plugin` name matches a checker compiled into the binary.

For example:

```json
{
  "intel_sources": [
    {
      "name": "Wise",
      "plugin": "Wise",
      "type": "IP",
      "enabled": true,
      "config": "{ \"url\" : \"http://wise:8081/ip/${ip}\" }"
    }
  ]
}
```

`config` is a string passed to the checker's initializer. Wise parses it as JSON and substitutes `${ip}` into the configured URL. [Nesd](../server/src/vuln/plugins/nesd.rs) also substitutes `${port}` and accepts `allow_low_severity`, which defaults to false. With that default it returns Medium, High, and Critical findings; enabling the option also includes Low findings.

The [sample Wise](../configs/intel_wise.json) and [Nesd](../configs/vuln_nessus.json) sources are enabled, but the supplied Compose examples do not provide their services. Disable these sources until those endpoints are deployed and reachable from the backend. The external Nesd service is part of the original Dsiem tools, not this Rust workspace.

Each uncached checker call has a 10-second timeout. The caches are configured in [intel.rs](../server/src/intel.rs) and [vuln.rs](../server/src/vuln.rs) with a 30-minute time-to-live and a 5-minute time-to-idle. Results are reinserted after access, so those settings should not be read as a guarantee that a frequently used entry is refreshed from its source every 30 minutes. `--cache` and `DSIEM_CACHEDURATION` are accepted by the CLI but are not connected to these caches.

The cache keys are IP for intel and IP/port for vulnerabilities; they do not include the checker identity. If you add multiple checkers, account for that shared-cache behavior before relying on independent results from each provider.

## Checker interfaces

An intel checker implements:

```rust
#[async_trait]
pub trait IntelChecker: Send + Sync {
    async fn check_ip(&self, ip: IpAddr) -> Result<HashSet<IntelResult>>;
    fn initialize(&mut self, config: String) -> Result<()>;
}
```

A vulnerability checker implements:

```rust
#[async_trait]
pub trait VulnChecker: Send + Sync {
    async fn check_ip_port(&self, ip: IpAddr, port: u16) -> Result<HashSet<VulnResult>>;
    fn initialize(&mut self, config: String) -> Result<()>;
}
```

Both result types contain `provider`, `term`, and `result` strings. Return an empty set when there is no match. The `term` identifies the queried address or address/port pair, and `result` supplies the text shown on the alarm.

## Adding a checker

1. [Build the server](building.md#server-binaries) before making changes.
2. Add a module under `server/src/intel/plugins/` or `server/src/vuln/plugins/`. Use [Wise](../server/src/intel/plugins/wise.rs) or [Nesd](../server/src/vuln/plugins/nesd.rs) as a starting point.
3. Declare that module in the corresponding `plugins/mod.rs`, construct it with `Checker::new`, and include it in `load_plugins()`'s returned vector. Choose a unique checker name and use that exact name in the JSON `plugin` field.
4. Add configuration to the frontend, rebuild the backend, and restart it so it downloads and initializes the new source.
5. Submit events that generate an alarm with an address the source can match. Check the backend logs and the alarm's `intel_hits` or `vulnerabilities` fields.

For local testing, run a NATS service reachable from the host and a frontend serving your configuration. The default Compose file does not publish NATS port 4222 to the host, so a host-built backend cannot use it without an override or another network arrangement. The telemetry Compose example does publish that port.

Use a separate configuration directory beside the test backend executable and a backend node assignment reserved for the test. Do not run two backends for the same directive set against the same event stream unless you intend to produce duplicate alarms. For example, after building and creating `target/debug/configs`:

```shell
cargo run --locked --bin dsiem-backend -- --debug serve \
  --node dsiem-backend-plugin-test \
  --frontend http://localhost:8080 \
  --msq nats://localhost:4222
```

The frontend must have a corresponding file such as `directives_dsiem-backend-plugin-test_custom.json`, valid assets, and the enabled checker configuration. Point checker URLs at addresses reachable from the process running this backend.
