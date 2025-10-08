use std::{collections::HashSet, net::IpAddr};

use anyhow::{Context, Result};
use async_trait::async_trait;
use serde::Deserialize;
use tracing::{debug, trace};

use super::{VulnChecker, VulnResult};

#[derive(Deserialize, Default)]
struct Config {
    url: String,
    allow_low_severity: Option<bool>,
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
        let allow_low_severity = self.config.allow_low_severity.unwrap_or(false);

        trace!(url, "nesd vuln check");

        let resp = reqwest::get(&url).await.context("get request error")?;
        let status = resp.status();
        let text = resp.text().await.context("error obtaining text")?;

        trace!(text, "nesd vuln check");

        let mut results: HashSet<VulnResult> = HashSet::new();

        if text == "no vulnerability found\n" {
            return Ok(results);
        }

        if status.as_u16() == 418 {
            // HTTP 418: I'm a teapot
            debug!(url, "nesd returned HTTP 418, indicating error in request, likely due to invalid IP or port");
            return Ok(results);
        }

        let res: Vec<NesdResult> = serde_json::from_str(&text).context("error parsing nesd result")?;

        for v in res.iter() {
            let is_valid = if allow_low_severity {
                v.risk == "Low" || v.risk == "Medium" || v.risk == "High" || v.risk == "Critical"
            } else {
                v.risk == "Medium" || v.risk == "High" || v.risk == "Critical"
            };
            if !is_valid {
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
