# Dsiem UI development

The UI is a Rust/Yew WebAssembly application. Use Rust with the `wasm32-unknown-unknown` target, Trunk, and Node.js/npm. The commands below follow the Trunk and Tailwind versions used by the [Docker UI builder](../deployments/docker/build/01.webui-builder).

```shell
cargo install --locked trunk --version 0.21.14
rustup target add wasm32-unknown-unknown
```

## Run the supporting services

Follow the [installation guide](../docs/installation.md) to start the lab and generate an alarm. Keep the frontend at `http://localhost:8080`, Elasticsearch at `http://localhost:9200`, and Kibana at `http://localhost:5601` for the default development proxy configuration.

The lab's Suricata capture uses a Linux host interface. A UI developer on another platform can use a remote lab and SSH tunnels for these ports.

## Run CSS and Trunk

From the repository root, start a CSS watcher in one terminal:

```shell
cd web
npm init -y
npm install text-spinners@1.0.5
npx --yes --package tailwindcss@3 tailwindcss -c ./tailwind.config.js -o ./tailwind.css --watch
```

In another terminal, also starting from the repository root:

```shell
cd web
trunk serve --public-url /ui --port 9000 index.html
```

Use `index.html`, which includes the Rust application entry. The current `index.dev.html` lacks that entry and references directories absent from this checkout.

[Trunk.toml](Trunk.toml) proxies `/config` and `/ui/assets` to the frontend on port 8080. The app needs `/config/dsiem_config.json` for status/tag choices and `/ui/assets/config/esconfig.json` for browser-facing Elasticsearch/Kibana URLs. Update the proxy targets if your frontend runs elsewhere.

## Open an alarm in the development UI

Open `http://localhost:9000/ui/#/data/alarm-detail/ALARM_ID` with an existing alarm ID, or change the bundled Kibana dashboard's link port before importing a development copy:

```shell
python3 - <<'PY'
from pathlib import Path
import shutil
import tempfile

dashboard_dir = Path(tempfile.mkdtemp(prefix="dsiem-dashboard-"))
for source in Path("deployments/kibana").glob("*.json"):
    shutil.copy2(source, dashboard_dir / source.name)
dashboard = dashboard_dir / "dashboard-siem.json"
dashboard.write_text(dashboard.read_text().replace(":8080", ":9000"))
print(dashboard)
PY
```

Run `./scripts/kbndashboard-import.sh localhost /the/printed/path/dashboard-siem.json` from the repository root. This updates the imported dashboard in the lab. Its `Dsiem Link` should now open the development server. The import helper also checks Elasticsearch at `localhost:9200`.

Trunk rebuilds the app when source files change, and the CSS watcher rebuilds the stylesheet. For a production bundle, use the [build instructions](../docs/building.md#browser-ui).
