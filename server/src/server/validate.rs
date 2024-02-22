use anyhow::{anyhow, Result};
use regex::Regex;
use serde_json::Value;
use tracing::debug;

use crate::{asset::NetworkAssets, directive::Directives, intel::IntelSources, vuln::VulnSources};

pub fn validate_filename(filename: &str) -> Result<bool> {
    let re = Regex::new(r"^[a-zA-Z0-9]([a-zA-Z0-9_-]+)?.json$")?;
    Ok(re.is_match(filename))
}

pub fn validate_content(filename: &str, content: &Value) -> Result<()> {
    debug!("validating content of {}", filename);
    let e = anyhow!("content doesn't have a valid entry");
    if filename.starts_with("assets_") {
        let res: NetworkAssets = serde_json::from_value(content.clone())?;
        if res.assets.is_empty() {
            return Err(e);
        }
    } else if filename.starts_with("intel_") {
        let res: IntelSources = serde_json::from_value(content.clone())?;
        if res.intel_sources.is_empty() {
            return Err(e);
        }
    } else if filename.starts_with("vuln_") {
        let res: VulnSources = serde_json::from_value(content.clone())?;
        if res.vuln_sources.is_empty() {
            return Err(e);
        }
    } else if filename.starts_with("directives_") {
        let res: Directives = serde_json::from_value(content.clone())?;
        if res.directives.is_empty() {
            return Err(e);
        }
    } else {
        return Err(anyhow!("unknown file type"));
    }
    Ok(())
}

#[cfg(test)]
use serde_json::json;
#[test]
fn test_validate_filename() -> Result<()> {
    assert!(validate_filename("foo_123-barCuX.json")?);
    assert!(!validate_filename("foo_123-barCuX!.json")?);
    assert!(!validate_filename("foo@bar.json")?);
    Ok(())
}

#[test]
fn test_validate_content() {
    assert!(validate_content("foo.json", &json!({})).is_err());

    let v = json!({
        "assets": [{
            "name": "Firewall",
            "cidr": "192.168.0.1/32",
            "value": 5
          }]
    });
    assert!(validate_content("assets_foo.json", &v).is_ok());
    let v = json!({ "assets": [] });
    assert!(validate_content("assets_foo.json", &v).is_err()); // empty

    let v = json!({
        "intel_sources": [{
            "name": "Wise",
            "plugin": "Wise",
            "type": "IP",
            "config": "",
            "enabled": true
        }]
    });
    assert!(validate_content("intel_foo.json", &v).is_ok());
    let v = json!({ "intel_sources": [] });
    assert!(validate_content("intel_foo.json", &v).is_err()); // empty

    let v = json!({
        "vuln_sources": [{
            "name": "Nessus",
            "plugin": "Nesd",
            "type": "IP-Port",
            "config": "",
            "enabled": true
        }]
    });
    assert!(validate_content("vuln_foo.json", &v).is_ok());
    let v = json!({ "vuln_sources": [] });
    assert!(validate_content("vuln_foo.json", &v).is_err()); // empty

    let v = json!({
      "directives": [
        {
          "name": "Ping Flood from SRC_IP",
          "kingdom": "Reconnaissance & Probing",
          "category": "Misc Activity",
          "id": 1,
          "priority": 3,
          "rules": [
            {
              "name": "ICMP Ping",
              "type": "PluginRule",
              "stage": 1,
              "plugin_id": 1001,
              "plugin_sid": [
                2100384
              ],
              "occurrence": 1,
              "from": "HOME_NET",
              "to": "ANY",
              "port_from": "ANY",
              "port_to": "ANY",
              "protocol": "ICMP",
              "reliability": 1,
              "timeout": 0
            }
          ]
        }
      ]
    });
    assert!(validate_content("directives_foo.json", &v).is_ok());
    let v = json!({ "directives": [] });
    assert!(validate_content("directives_foo.json", &v).is_err()); // empty
}
