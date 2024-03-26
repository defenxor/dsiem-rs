use std::{collections::HashMap, net::IpAddr, str::FromStr};

use arcstr::ArcStr;
use chrono::prelude::*;
use serde::Serialize;
use serde_derive::Deserialize;

#[derive(Deserialize, Serialize, Clone, Debug)]
pub struct NormalizedEvent {
    // refer to https://github.com/defenxor/dsiem-rs/blob/master/docs/dsiem_plugin.md#normalized-event

    // required fields
    #[serde(rename(deserialize = "event_id", serialize = "event_id"))]
    pub id: String,
    pub timestamp: DateTime<Utc>,
    pub sensor: ArcStr,
    pub title: ArcStr,
    pub src_ip: IpAddr,
    pub dst_ip: IpAddr,

    // required fields, but enforcement will be done by validation
    #[serde(default)]
    pub plugin_id: u64,
    #[serde(default)]
    pub plugin_sid: u64,
    #[serde(default)]
    pub product: ArcStr,
    #[serde(default)]
    pub category: ArcStr,

    // optionals
    #[serde(default)]
    pub subcategory: ArcStr,
    #[serde(default)]
    pub src_port: u16,
    #[serde(default)]
    pub dst_port: u16,
    #[serde(default)]
    pub protocol: ArcStr,
    #[serde(default)]
    pub conn_id: u64,
    #[serde(default)]
    pub custom_data1: ArcStr,
    #[serde(default)]
    pub custom_label1: ArcStr,
    #[serde(default)]
    pub custom_data2: ArcStr,
    #[serde(default)]
    pub custom_label2: ArcStr,
    #[serde(default)]
    pub custom_data3: ArcStr,
    #[serde(default)]
    pub custom_label3: ArcStr,
    #[serde(default)]
    pub rcvd_time: i64, // for backpressure control
    #[serde(default)]
    pub carrier: HashMap<String, String>,
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
            sensor: "".into(),
            protocol: "".into(),
            title: "".into(),
            conn_id: 0,
            plugin_id: 0,
            plugin_sid: 0,
            product: "".into(),
            category: "".into(),
            subcategory: "".into(),
            custom_data1: "".into(),
            custom_label1: "".into(),
            custom_data2: "".into(),
            custom_label2: "".into(),
            custom_data3: "".into(),
            custom_label3: "".into(),
            rcvd_time: 0,
            carrier: HashMap::new(),
        }
    }
}

impl NormalizedEvent {
    pub fn valid(&self) -> bool {
        // timestamp, src_ip, and dst_ip are always valid
        !self.title.is_empty()
            && !self.sensor.is_empty()
            && !self.id.is_empty()
            && ((self.plugin_id != 0 && self.plugin_sid != 0)
                || (!self.product.is_empty() && !self.category.is_empty()))
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_event() {
        let mut e = NormalizedEvent::default();
        assert!(!e.valid());

        // make sure each required field is actually required

        e.id = "foo".to_owned();
        assert!(!e.valid());
        e.title = "bar".into();
        assert!(!e.valid());
        e.timestamp = Utc::now();
        assert!(!e.valid());
        e.src_ip = IpAddr::from_str("0.0.0.0").unwrap();
        assert!(!e.valid());
        e.dst_ip = IpAddr::from_str("0.0.0.0").unwrap();
        assert!(!e.valid());
        e.sensor = "qux".into();
        assert!(!e.valid());

        e.plugin_id = 1001;
        assert!(!e.valid());
        e.plugin_sid = 1;
        assert!(e.valid());

        let e2 = e.clone();
        assert!(e.id == e2.id);

        assert!(e.valid());
        e.plugin_id = 0;
        assert!(!e.valid());

        e.product = "iptables".into();
        assert!(!e.valid());
        e.category = "Firewall".into();
        assert!(e.valid());

        let s = r#"
        {
            "event_id": "missing req fields",
            "timestamp": "2023-01-01T00:00:00Z",
            "title": "foo",
            "src_ip":"10.0.0.3",
            "dst_ip":"0.0.0.0",
            "sensor": "foo"
        }"#;
        let e3: NormalizedEvent = serde_json::from_str(s).unwrap();
        assert!(!e3.valid());
    }
}
