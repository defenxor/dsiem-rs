# Dsiem Command and Tools

## Usage Information

All executables and their sub-commands have `-h` or `--help` flag that will outline and describe all available parameters. For example:

```shell
$ ./dsiem-frontend -h
Dsiem frontend server

Usage: 

Commands:
  serve  Start Dsiem frontend server
  help   Print this message or the help of the given subcommand(s)

Options:
  -v, --verbosity...  Increase logging verbosity
      --debug         Enable debug output, for compatibility purpose [env: DSIEM_DEBUG=]
      --trace         Enable trace output, for compatibility purpose [env: DSIEM_TRACE=]
  -j, --json          Enable json-lines log output [env: DSIEM_JSON=]
      --test-env      Testing environment flag
  -h, --help          Print help (see more with '--help')
  -V, --version       Print version
```

```shell
$ ./dsiem-frontend serve -h
Start Dsiem frontend server

Usage: 

Options:
  -a, --ip-address <ip>
          IP address for the HTTP server to listen on [env: DSIEM_ADDRESS=] [default: 0.0.0.0]
  -p, --tcp-port <tcp>
          TCP port for the HTTP server to listen on [env: DSIEM_PORT=] [default: 8080]
  -n, --node <string>
          Unique node name to use when deployed in cluster mode [env: DSIEM_NODE=]
  -e, --max_eps <number>
          [env: MAX_EPS=] [default: 1000]
  -i, --min_eps <number>
          [env: MIN_EPS=] [default: 100]
      --msq <string>
          Nats address to use for frontend - backend communication [env: DSIEM_MSQ=] [default: nats://dsiem-nats:4222]
  -q, --max_queue <events>
          Length of queue for unprocessed events, setting this to 0 will use 1,000,000 events to emulate unbounded queue [env: DSIEM_MAXQUEUE=] [default: 25000]
      --writable-config
          Whether to allow configuration file update through HTTP [env: DSIEM_WRITEABLECONFIG=]
  -s, --status <comma separated strings>
          Alarm status to use, the first one will be assigned to new alarms [env: DSIEM_STATUS=] [default: Open,In-Progress,Closed]
  -t, --tags <comma separated strings>
          Alarm tags to use, the first one will be assigned to new alarms [env: DSIEM_TAGS=] [default: "Identified Threat,False Positive,Valid Threat,Security Incident"]
  -h, --help
          Print help (see more with '--help')
```

Each flag can be configured through command line parameter or environment variable. As an example, it is possible to execute `./dsiem-frontend serve` above with `node` set to `dsiem-0` like this:

```shell
$ ./dsiem-frontend serve --node=dsiem-0
```
or
```shell
$ export DSIEM_NODE=dsiem-0
$ ./dsiem-frontend serve
```

Notice how the environment variable above starts with `DSIEM_` string. The same applies for all parameters, so to configure the `max_eps` flag, you will need to set environment variable `DSIEM_MAXEPS`, and so on.

We try to provide sensible defaults, so there's no need to supply additional flags unless there's a specific need to override them. Refer to the [Installation](./installation.md) doc for examples on how to start both the frontend and backend dsiem nodes.