use cidr::IpCidr;
use serde::Serialize;
use serde_derive::Deserialize;
use std::{fs, net::IpAddr};
extern crate glob;
use anyhow::{anyhow, Result};
use glob::glob;
use tracing::info;

use crate::utils;

const ASSETS_GLOB: &str = "assets_*.json";

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct NetworkAsset {
    pub name: String,
    pub cidr: IpCidr,
    #[serde(default)]
    pub value: u8,
    #[serde(default)]
    pub whitelisted: bool,
}

#[derive(Serialize, Deserialize, Clone, Default, Debug)]
pub struct NetworkAssets {
    pub assets: Vec<NetworkAsset>,
    #[serde(skip_deserializing)]
    whitelist: Vec<IpCidr>,
    #[serde(skip_deserializing)]
    pub home_net: Vec<IpCidr>,
}

impl NetworkAssets {
    pub fn from_string(s: String) -> Result<NetworkAssets> {
        let mut result = NetworkAssets {
            assets: vec![],
            whitelist: vec![],
            home_net: vec![],
        };
        let loaded: NetworkAssets = serde_json::from_str(&s)?;
        for a in loaded.assets {
            validate_asset(&a)?;
            result.assets.push(a.clone());
            if a.whitelisted {
                result.whitelist.push(a.cidr);
            } else {
                result.home_net.push(a.cidr);
            }
        }
        Ok(result)
    }
    pub fn new(test_env: bool, subdir: Option<Vec<String>>) -> Result<NetworkAssets> {
        let cfg_dir = utils::config_dir(test_env, subdir)?;
        let glob_pattern = cfg_dir.to_string_lossy().to_string() + "/" + ASSETS_GLOB;
        let mut result = NetworkAssets {
            assets: vec![],
            whitelist: vec![],
            home_net: vec![],
        };
        for file_path in glob(&glob_pattern)?.flatten() {
            info!("reading {:?}", file_path);
            let s = fs::read_to_string(file_path)?;
            let mut r = NetworkAssets::from_string(s)?;
            result.assets.append(&mut r.assets);
            result.whitelist.append(&mut r.whitelist);
            result.home_net.append(&mut r.home_net);
        }
        if result.assets.is_empty() {
            return Err(anyhow!("cannot load any asset"));
        }
        info!("{} assets found and loaded", result.assets.len());
        result.assets.shrink_to_fit();
        Ok(result)
    }
    pub fn is_in_homenet(&self, ip: &IpAddr) -> bool {
        for net in &self.home_net {
            if net.contains(ip) {
                return true;
            }
        }
        false
    }
    pub fn is_whitelisted(&self, ip: &IpAddr) -> bool {
        for net in &self.whitelist {
            if net.contains(ip) {
                return true;
            }
        }
        false
    }

    pub fn get_value(&self, ip: &IpAddr) -> u8 {
        self.assets
            .iter()
            .filter(|n| n.cidr.contains(ip))
            .max_by_key(|x| x.value)
            .map(|x| x.value)
            .unwrap_or_default()
    }
    pub fn get_asset_networks(&self, ip: &IpAddr) -> Option<Vec<String>> {
        let networks = self
            .home_net
            .iter()
            .filter(|n| n.contains(ip) && !n.is_host_address())
            .map(|v| v.to_string())
            .collect::<Vec<String>>();
        if networks.is_empty() {
            None
        } else {
            Some(networks)
        }
    }

    pub fn get_name(&self, ip: &IpAddr) -> Result<String> {
        let asset = self
            .assets
            .clone()
            .into_iter()
            .filter(|n| n.cidr.contains(ip))
            .filter(|n| n.cidr.is_host_address())
            .take(1)
            .collect::<Vec<NetworkAsset>>();
        if asset.is_empty() {
            return Err(anyhow!("cannot get the asset name for {}", ip));
        }
        Ok(asset[0].name.clone())
    }
}

fn validate_asset(asset: &NetworkAsset) -> Result<()> {
    if asset.value == 0 {
        return Err(anyhow!("asset {} value cannot be 0", asset.name));
    }
    if asset.name.is_empty() {
        return Err(anyhow!("asset name cannot be empty"));
    }
    Ok(())
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    #[test]
    fn test_assets() {
        let subdir = Some(vec!["assets".to_string()]);
        let res = NetworkAssets::new(false, None);
        assert_eq!(res.unwrap_err().to_string(), "cannot load any asset");
        let assets = NetworkAssets::new(true, subdir).unwrap();
        let ip1: IpAddr = "192.168.0.1".parse().unwrap();
        let name = assets.get_name(&ip1).unwrap();
        assert_eq!(name, "Firewall".to_string());
        let networks = assets.get_asset_networks(&ip1).unwrap();
        assert_eq!(networks, vec!["192.168.0.0/16"]);
        assert!(assets.is_in_homenet(&ip1));
        let ip2: IpAddr = "192.168.0.2".parse().unwrap();
        assert!(assets.is_whitelisted(&ip2));
        assert_eq!(assets.get_value(&ip1), 5);
        let ip3: IpAddr = "8.8.8.8".parse().unwrap();
        let name = assets.get_name(&ip3);
        let networks = assets.get_asset_networks(&ip3);
        assert!(networks.is_none());
        assert!(name.is_err());
        if let Err(e) = name {
            assert_eq!(e.to_string(), "cannot get the asset name for 8.8.8.8");
        }
        assert!(!assets.is_in_homenet(&ip3));
        assert!(!assets.is_whitelisted(&ip3));

        let mut a = NetworkAsset {
            cidr: IpCidr::from_str("192.168.0.1/32").unwrap(),
            name: "foo".to_string(),
            value: 0,
            whitelisted: false,
        };
        assert_eq!(
            validate_asset(&a).unwrap_err().to_string(),
            "asset foo value cannot be 0"
        );
        a.value = 5;
        a.name = "".to_string();
        assert_eq!(
            validate_asset(&a).unwrap_err().to_string(),
            "asset name cannot be empty"
        );

        let ip2: IpAddr = "2002:c0a8:0001:0:0:0:0:1".parse().unwrap();
        assert!(assets.is_in_homenet(&ip2));
        let name = assets.get_name(&ip2).unwrap();
        assert_eq!(name, "firewall-ipv6".to_string());
        assert_eq!(assets.get_value(&ip2), 5);

        let net = assets.get_asset_networks(&ip2).unwrap();
        assert_eq!(net, vec!["2002:c0a8:1::/64".to_string()])
    }
}
