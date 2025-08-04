use std::{collections::HashSet, net::IpAddr};

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use tracing::{debug, trace};

use super::{VulnChecker, VulnResult};

#[derive(Deserialize, Default)]
struct Config {
    url: String,
}
#[derive(Default)]
pub struct Nesd {
    config: Config,
}

#[derive(Deserialize)]
pub struct NesdResult {
    #[serde(default)]
    cve: String,
    risk: String,
    name: String,
}

#[async_trait]
impl VulnChecker for Nesd {
    async fn check_ip_port(&self, ip: IpAddr, port: u16) -> Result<HashSet<VulnResult>> {
        let url = self.config.url.replacen("${ip}", &ip.to_string(), 1).replacen("${port}", &port.to_string(), 1);

        trace!(url, "nesd vuln check");

        let resp = reqwest::get(&url).await.context("get request error")?;
        let status = resp.status();
        let text = resp.text().await.context("error obtaining text")?;

        trace!(text, "nesd vuln check");

        let mut results: HashSet<VulnResult> = HashSet::new();

        if status.as_u16() == 418 {
            // HTTP 418: I'm a teapot
            debug!(url, "nesd returned HTTP 418, indicating error in request, likely due to invalid IP or port");
            return Ok(results);
        }

        if text == "no vulnerability found\n" {
            return Ok(results);
        }

        let res: Vec<NesdResult> = serde_json::from_str(&text).context("error parsing nesd result")?;

        for v in res.iter() {
            if v.risk != "Medium" && v.risk != "High" && v.risk != "Critical" {
                continue;
            }

            let mut s = v.risk.clone() + " - " + &v.name;
            if !v.cve.is_empty() {
                s = s + " (" + &v.cve + ")";
            }
            let term = ip.to_string() + ":" + &port.to_string();

            let r = VulnResult { provider: "Nesd".to_owned(), term, result: s };
            results.insert(r);
        }

        Ok(results)
    }

    fn initialize(&mut self, config: String) -> Result<()> {
        let c = serde_json::from_str(&config).context("error parsing nesd config")?;
        self.config = c;
        Ok(())
    }
}
