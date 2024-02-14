use std::{ net::IpAddr, str::FromStr };

use chrono::prelude::*;
use serde::Serialize;
use serde_derive::Deserialize;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct NormalizedEvent {
    #[serde(rename(deserialize = "event_id", serialize = "event_id"))]
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub sensor: String,
    pub protocol: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub conn_id: u64,
    #[serde(default)]
    pub plugin_id: u64,
    #[serde(default)]
    pub plugin_sid: u64,
    #[serde(default)]
    pub product: String,
    #[serde(default)]
    pub category: String,
    #[serde(default)]
    pub subcategory: String,
    #[serde(default)]
    pub custom_data1: String,
    #[serde(default)]
    pub custom_label1: String,
    #[serde(default)]
    pub custom_data2: String,
    #[serde(default)]
    pub custom_label2: String,
    #[serde(default)]
    pub custom_data3: String,
    #[serde(default)]
    pub custom_label3: String,
    #[serde(default)]
    pub rcvd_time: i64, // for backpressure control
}

impl Default for NormalizedEvent {
    fn default() -> Self {
        NormalizedEvent {
            id: "".to_owned(),
            timestamp: Utc::now(),
            src_ip: IpAddr::from_str("0.0.0.0").unwrap(),
            dst_ip: IpAddr::from_str("0.0.0.0").unwrap(),
            src_port: 0,
            dst_port: 0,
            sensor: "".to_owned(),
            protocol: "".to_owned(),
            title: "".to_owned(),
            conn_id: 0,
            plugin_id: 0,
            plugin_sid: 0,
            product: "".to_owned(),
            category: "".to_owned(),
            subcategory: "".to_owned(),
            custom_data1: "".to_owned(),
            custom_label1: "".to_owned(),
            custom_data2: "".to_owned(),
            custom_label2: "".to_owned(),
            custom_data3: "".to_owned(),
            custom_label3: "".to_owned(),
            rcvd_time: 0,
        }
    }
}

impl NormalizedEvent {
    pub fn valid(&self) -> bool {
        (self.plugin_id != 0 && self.plugin_sid != 0) ||
            (!self.product.is_empty() && !self.category.is_empty())
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_event() {
        let mut e = NormalizedEvent {
            id: "foo".to_owned(),
            plugin_id: 1001,
            plugin_sid: 1,
            ..Default::default()
        };
        let e2 = e.clone();
        assert!(e.id == e2.id);

        assert!(e.valid());
        e.plugin_id = 0;
        assert!(!e.valid());
        e.product = "iptables".to_owned();
        e.category = "Firewall".to_owned();
        assert!(e.valid());

        let s =
            r#"{"event_id":"bar", "timestamp": "2023-01-01T00:00:00Z","src_ip":"10.0.0.3", "dst_ip":"0.0.0.0", "src_port": 80, "dst_port": 0, "sensor": "foo", "protocol":"TCP" }"#;
        let e3: NormalizedEvent = serde_json::from_str(s).unwrap();
        assert!(!e3.valid());
    }
}
