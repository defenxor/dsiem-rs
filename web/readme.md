# Dsiem UI

## Development

### Requirements

- Setup [Rust development](https://www.rust-lang.org/tools/install) environment on Linux.
- Install minimal [NodeJs](https://nodejs.org/en/download/) tools too, they'll be used to get CSS files.
- Install `trunk` command:
```shell
cargo install --locked trunk
```
- Install `wasm32-unknown-unknown` target:
```shell
rustup target add wasm32-unknown-unknown
```

### Setup

All steps below should be run from the repo root directory.

```shell
export ROOT_DIR=$(git rev-parse --show-toplevel)
echo $ROOT_DIR
```

- First run the example docker compose environment:

```shell
cd ./deployments/docker && \
PROMISC_INTERFACE=eth0 docker-compose up
```

- On another terminal, run tailwind CSS in watch mode:
```shell
./scripts/css.sh dev
```

- On another terminal, run trunk serve:
```shell
cd ./web && trunk serve --public-url /ui --port 9000
```

- Update `Dsiem Link` scripted field in the default Kibana dashboard to use trunk serve above.
```shell
cp ./deployments/kibana/* /tmp/
sed -i 's/8080/9000/' /tmp/dashboard-siem.json
./scripts/kbndashboard-import.sh localhost /tmp/dashboard-siem.json 
```

- From another terminal, trigger an alarm by pinging the IP address of the `${PROMISC_INTERFACE}`. The example above uses `eth0`, so the corresponding command will be:
```shell
ip a | grep inet | grep eth0
ping [the ip address]
```

- Open the SIEM dashboard in Kibana (`http://localhost:5601`). The alarms `Dsiem Link` should open the app served by trunk above in a new tab.

- Any modification to source files in `src` or the CSS file should trigger a page live reload.