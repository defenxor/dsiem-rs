# Differences from OSSIM

Dsiem uses an OSSIM-style normalized event model and risk formula. Its runtime and deployment scope differ: the Rust binaries perform correlation, while the surrounding pipeline handles log collection and storage. This repository also includes a browser UI for alarm investigation. See the [project overview](../README.md).

## Vulnerability information

Dsiem looks up vulnerability information using source and destination IP/port pairs from matched events. It does not map the event's signature to a CVE and use that mapping to change rule reliability. Vulnerability and threat-intelligence matches enrich the alarm without changing its risk score. Analysts must assess whether those results relate to the activity being investigated.

The lookup interfaces and current implementations are described in [lookup plugins](ti_vuln_plugins.md).

## Rule stages

Dsiem directives have a linear sequence of stages. Express alternative detection paths as separate directives. A later stage can refer to values from the first event of an earlier stage.

The `all_rules_always_active` flag lets a backlog retain additional events from completed stages. For example, a directive can use these stages:

```text
all_rules_always_active: true
stage 1: one failed SSH login
stage 2: four more failed logins, timeout 300 seconds
stage 3: one successful login, timeout 300 seconds
```

Configure later stages to refer to the source/destination values from stage 1 when those addresses should remain the same. While stage 3 is active, a failed login that does not match stage 3 can still be attached to an earlier matching stage. This can prevent it from starting another backlog. Matching earlier stages does not advance stage 3 or raise risk.

Each timeout applies to its own stage, with the start-time and expiration behavior described in [directive and alarm](directive_and_alarm.md). Two 300-second stages do not enforce one overall five-minute window.

## Migration checks

- Both IPv4 and IPv6 are supported. Define assets explicitly; addresses outside the configured assets have value zero.
- Risk is an integer. Fractional results are discarded.
- Include required rule fields such as `port_from`, `port_to`, `protocol`, and `timeout`. Use `ANY` for unrestricted ports.
- Keep stage numbers consecutive from 1 and references pointed at earlier stages.
- Enabled directives that fail validation stop backend startup; disabled directives are skipped.
- Deploy frontend and backend binaries with NATS. There is no standalone mode in this repository.

Use the [command reference](commands.md) and [directive reference](directive_and_alarm.md) when adapting an existing configuration.
