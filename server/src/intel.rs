use anyhow::Result;
use async_trait::async_trait;
use glob::glob;
use mini_moka::sync::Cache;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, fmt, fs, net::IpAddr, sync::Arc, time::Duration};
use tracing::{debug, info, instrument};

use crate::utils;

mod plugins;

const INTEL_GLOB: &str = "intel_*.json";
const INTEL_MAX_SECONDS: u64 = 10;

#[derive(Deserialize, Clone, Debug)]
pub struct IntelSource {
    pub name: String,
    #[serde(rename(deserialize = "type"))]
    pub source_type: String,
    pub enabled: bool,
    pub plugin: String,
    pub config: String,
}

#[derive(Deserialize, Debug)]
pub struct IntelSources {
    pub intel_sources: Vec<IntelSource>,
}

#[derive(Hash, Eq, PartialEq, Default, Serialize, Deserialize, Debug, Clone)]
pub struct IntelResult {
    pub provider: String,
    pub term: String,
    pub result: String,
}

#[async_trait]
pub trait IntelChecker: Send + Sync {
    async fn check_ip(&self, ip: IpAddr) -> Result<HashSet<IntelResult>>;
    fn initialize(&mut self, config: String) -> Result<()>;
}

pub struct IntelPlugin {
    pub checkers: Arc<Vec<plugins::Checker>>,
    cache: Cache<IpAddr, HashSet<IntelResult>>,
    // only used for debug trait, required by backlog struct
    pub intel_sources: Vec<IntelSource>,
}

impl fmt::Debug for IntelPlugin {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self.intel_sources)
    }
}

impl IntelPlugin {
    #[instrument(name = "intel_checkers")]
    pub async fn run_checkers(
        &self,
        check_private_ip: bool,
        targets: HashSet<IpAddr>,
    ) -> Result<HashSet<IntelResult>> {
        let mut set = HashSet::new();
        for c in self.checkers.iter() {
            for ip in targets.iter() {
                if !check_private_ip && !ip_rfc::global(ip) {
                    debug!("skipping private IP {}", ip);
                    continue;
                }
                let res = if let Some(v) = self.cache.get(ip) {
                    debug!("returning intel result from cache for {}", ip);
                    v
                } else {
                    let v = tokio::time::timeout(
                        Duration::from_secs(INTEL_MAX_SECONDS),
                        c.plugin.check_ip(*ip),
                    )
                    .await??;
                    debug!("obtained intel result for {}", ip);
                    v
                };
                set.extend(res.clone());
                self.cache.insert(*ip, res);
            }
        }
        Ok(set)
    }
}

pub fn load_intel(test_env: bool, subdir: Option<Vec<String>>) -> Result<IntelPlugin> {
    let cfg_dir = utils::config_dir(test_env, subdir)?;
    let glob_pattern = cfg_dir.to_string_lossy().to_string() + "/" + INTEL_GLOB;
    let mut intels = vec![];
    let mut checkers = plugins::load_plugins();

    for file_path in glob(&glob_pattern)?.flatten() {
        info!("reading {:?}", file_path);
        let s = fs::read_to_string(file_path)?;
        let loaded: IntelSources = serde_json::from_str(&s)?;
        for s in loaded.intel_sources {
            if s.enabled {
                for p in checkers.iter_mut() {
                    if p.name == s.plugin {
                        p.plugin.initialize(s.config.clone())?;
                        p.enabled = true;
                        intels.push(s.clone());
                    }
                }
            }
        }
    }
    checkers.retain(|c| c.enabled);

    let len = checkers.len();
    if len > 0 {
        info!("loaded {} intel plugins", len);
    }

    let cache = Cache::builder()
        // Time to live (TTL): 30 minutes
        .time_to_live(Duration::from_secs(30 * 60))
        // Time to idle (TTI):  5 minutes
        .time_to_idle(Duration::from_secs(5 * 60))
        // Create the cache.
        .build();

    checkers.shrink_to_fit();
    let res = IntelPlugin {
        intel_sources: intels,
        checkers: Arc::new(checkers),
        cache,
    };
    Ok(res)
}

#[cfg(test)]
mod test {
    use tokio::join;

    use super::*;

    #[tokio::test]
    async fn test_intel() {
        let intels = load_intel(true, Some(vec!["intel_vuln".to_string()])).unwrap();
        // uncommend the struct Debug impl and struct member var to see the intel_sources
        // debug!("intels: {:?}", intels);
        assert!(intels.checkers.len() == 1); // wise, change this if there's anything else
        let mut set = HashSet::new();
        let ip1: IpAddr = "192.168.0.1".parse().unwrap();
        let ip2: IpAddr = "1.0.0.1".parse().unwrap();
        let ip3: IpAddr = "1.0.0.2".parse().unwrap();
        set.insert(ip1);
        set.insert(ip2);
        set.insert(ip3);
        let res = intels.run_checkers(false, set.clone()).await;
        assert!(res.is_err());
        let str_err = res.unwrap_err().to_string();
        assert!(str_err == "get request error" || str_err == "deadline has elapsed");

        let mut server = mockito::Server::new_with_port_async(18081).await;
        let _m1 = server
            .mock("GET", "/ip/1.0.0.1")
            .with_status(200)
            .with_body(
                r#"[{field: "description", len: 4, value: "blacklisted localnet -- testing only"}]"#
            )
            .create_async();
        let _m2 = server
            .mock("GET", "/ip/192.168.0.1")
            .with_status(200)
            .with_body(
                r#"[{field: "description", len: 37, value: "blacklisted localnet -- testing only"}]"#
            )
            .create_async();
        let _m3 = server
            .mock("GET", "/ip/1.0.0.2")
            .with_status(200)
            .with_body(
                r#"[{field: "description", len: 40, value: "blacklisted localnet -- testing only"}]"#
            )
            .create_async();
        join!(_m1, _m2, _m3);

        let result_set = intels.run_checkers(false, set.clone()).await.unwrap();
        // 1.0.0.1 has len < 5 and is filtered by wise plugin
        assert_eq!(result_set.len(), 1);
        // run again to use cache
        _ = intels.run_checkers(true, set).await.unwrap();
    }
}
