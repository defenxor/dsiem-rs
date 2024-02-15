# Threat Intelligence and Vulnerability Lookup Plugins

Threat intel plugin enriches content of an alarm whenever it involves a public IP address that is listed in one of the plugin backend databases. The same goes for Vulnerability lookup plugin, but here the search is done based on IP and port combination, and the alarm's IP address to lookup will also include any private IP addresses.

## About Threat Intel Lookup Plugin

Intel lookup plugin is simply a Rust crate that implements the following trait:
```rust
#[async_trait]
pub trait IntelChecker: Send + Sync {
    async fn check_ip(&self, ip: IpAddr) -> Result<HashSet<IntelResult>>;
    fn initialize(&mut self, config: String) -> Result<()>;
}
```

`initialize` will receive its `config` content from the text defined in `configs/intel_*.json` file. This allows user to pass in
custom data in any format to the plugin to configure its behavior.

`check_ip` will receive its `ip` parameter from SIEM alarm's source and destination IP addresses. The plugin should then check that address against its sources (e.g. by database lookups, API calls, etc.), and return a `HashSet<IntelResult>` if there's a matching entry for it. If that's the case, Dsiem expects the plugin to also return more detail information in multiple `intel.Result` struct as follows:

```rust
pub struct IntelResult {
    pub provider: String,
    pub term: String,
    pub result: String,
}
```

You can see a working example of this in [Wise](https://github.com/defenxor/dsiem-rs/blob/master/server/src/intel/plugins/wise.rs) intel plugin code. The plugin uses `initialize` function to obtain Wise URL to use from the JSON [config file](https://github.com/defenxor/dsiem-rs/blob/master/configs/intel_wise.json).

```JSON
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

## About Vulnerability Lookup Plugin

Vulnerability lookup plugin is a Rust crate that implements the following trait:

```rust
#[async_trait]
pub trait VulnChecker: Send + Sync {
    async fn check_ip_port(&self, ip: IpAddr, port: u16) -> Result<HashSet<VulnResult>>;
    fn initialize(&mut self, config: String) -> Result<()>;
}
```

The difference with intel plugin is that `check_ip_port` here will receive `ip` and `port` combination instead of just `ip`. Those parameters will also come from alarm data, like source IP and source port, or destination IP and destination port.

A working example of this can be found in [Nesd](https://github.com/defenxor/dsiem-rs/blob/master/server/src/vuln/plugins/nesd.rs) plugin code. The plugin uses `initialize` function to obtain Nesd URL to use from the JSON [config file](https://github.com/defenxor/dsiem-rs/blob/master/configs/vuln_nessus.json).

## Developing Intel or Vulnerability Lookup Plugin

First you need a working Rust development environment. Just follow the instruction from [here](https://www.rust-lang.org/tools/install) to get started.

Next clone this repository and test the build process. Example on a Linux or OSX system:

```bash
$ git clone https://github.com/defenxor/dsiem-rs
$ cd dsiem-rs
$ cargo build
```

You should now have a `dsiem-frontend` and `dsiem-backend` binary in `./target/debug/` directory, and ready to start developing a plugin.

A quick way of creating a new intel plugin by using Wise as template is shown below. The same steps should also apply for making a new vulnerability lookup plugin based on Nesd.

```shell
# prepare the new plugin files based on wise
$ cp server/src/intel/plugins/wise.rs server/src/intel/plugins/myintel.rs

# replace wise -> myintel and Wise -> Myintel in the code
$ sed -i 's/wise/myintel/g; s/Wise/Myintel/g' server/src/intel/plugins/myintel.rs

# do the same for config file
$ cp configs/intel_wise.json configs/intel_myintel.json
$ sed -i 's/Wise/Myintel/g; s/wise/myintel/g' configs/intel_myintel.json

# insert entry in intel plugins
$ export MODFILE=server/src/intel/plugins/mod.rs
$ sed -i '4 i mod myintel;' ${MODFILE}
$ sed -i '24 i let myintel = Checker::new(Box::<myintel::Myintel>::default(), "Myintel");' ${MODFILE}
$ sed -i 's/vec!\[wise\]/vec!\[wise, myintel\]/' ${MODFILE}

# rebuild dsiem binary to include the new plugin
$ cargo build
```

After that, you can start dsiem and verify that the plugin is loaded correctly like so:

- Run the docker-compose example environment in a separate terminal:

  ```shell
  $ cd deployments/docker && PROMISC_INTERFACE=eth0 docker-compose up
  ```

- Copy the new plugin config file to the expected location:

  ```shell
  $ mkdir -p target/debug/configs && cp configs/intel_myintel.json target/debug/configs/
  ```

- Run `dsiem-backend` and filter for relevant entries:

  ```shell
  $ cargo run --bin dsiem-backend -- serve -n dsiem-backend-0 -f http://localhost:8080 2>&1 | grep intel
  2024-02-15T02:30:23.280219Z  INFO dsiem::intel: reading "/home/mmta/proj/dsiem-rs/target/debug/configs/intel_myintel.json"
  2024-02-15T02:30:23.280263Z  INFO dsiem::intel: reading "/home/mmta/proj/dsiem-rs/target/debug/configs/intel_wise.json"
  2024-02-15T02:30:23.280284Z  INFO dsiem::intel: loaded 2 intel plugins
  ```

And that's it. From here on you can start editing `server/src/intel/plugins/myintel.rs` to implement your plugin's unique functionality. Don't forget to send PR when you're done ;).
