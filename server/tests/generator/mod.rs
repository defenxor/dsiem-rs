use std::{
    collections::HashMap,
    net::{IpAddr, Ipv4Addr},
    str::FromStr,
    thread::sleep,
};

use dsiem::{
    event::NormalizedEvent,
    rule::{DirectiveRule, RuleType},
};
use nanoid::nanoid;

const MAX_EVENT_FOR_A_STAGE: usize = 100;
const IP_IN_HOME_NET: &str = "192.168.0.1"; // must match an entry in assets.json

pub fn generate_normalized_event(rules: &[DirectiveRule]) -> Vec<NormalizedEvent> {
    let mut res = vec![];
    let mut ref_events = HashMap::new();
    for r in rules {
        let mut c = 0;
        for _ in 0..r.occurrence {
            c += 1;
            if c > MAX_EVENT_FOR_A_STAGE {
                break;
            }
            let mut e = NormalizedEvent { id: nanoid!(9), ..Default::default() };
            sleep(std::time::Duration::from_millis(100));

            e.rcvd_time = e.timestamp.timestamp_millis();

            match r.rule_type {
                RuleType::TaxonomyRule => {
                    e.product = if !r.product.is_empty() { r.product[0].clone() } else { "".into() };
                    e.category = r.category.clone();
                }
                RuleType::PluginRule => {
                    e.plugin_id = r.plugin_id;
                    e.plugin_sid = r.plugin_sid[0];
                }
            };

            let src_ip = use_ref_or_set(r.from.to_string(), ReferableField::From, &ref_events);
            e.src_ip = IpAddr::from_str(&src_ip).unwrap();

            let dst_ip = use_ref_or_set(r.to.to_string(), ReferableField::To, &ref_events);
            e.dst_ip = IpAddr::from_str(&dst_ip).unwrap();

            e.src_port =
                use_ref_or_set(r.port_from.to_string(), ReferableField::PortFrom, &ref_events).parse().unwrap();

            e.dst_port = use_ref_or_set(r.port_to.to_string(), ReferableField::PortTo, &ref_events).parse().unwrap();

            e.protocol = use_ref_or_set(r.protocol.to_string(), ReferableField::Protocol, &ref_events).parse().unwrap();

            e.custom_data1 =
                use_ref_or_set(r.custom_data1.to_string(), ReferableField::CustomData1, &ref_events).parse().unwrap();
            e.custom_label1 = if e.custom_data1.is_empty() { "".into() } else { "label1".into() };

            e.custom_data2 =
                use_ref_or_set(r.custom_data2.to_string(), ReferableField::CustomData2, &ref_events).parse().unwrap();
            e.custom_label2 = if e.custom_data2.is_empty() { "".into() } else { "label2".into() };

            e.custom_data3 =
                use_ref_or_set(r.custom_data3.to_string(), ReferableField::CustomData3, &ref_events).parse().unwrap();
            e.custom_label3 = if e.custom_data3.is_empty() { "".into() } else { "label3".into() };

            e.title = if r.name.contains("SRC_IP") || r.name.contains("DST_IP") {
                r.name.clone().replace("SRC_IP", &e.src_ip.to_string()).replace("DST_IP", &e.dst_ip.to_string()).into()
            } else {
                r.name.clone().into()
            };

            e.sensor = "dsiem-test".into();

            res.push(e.clone());
            // this saves the first event that is generated for a stage
            ref_events.entry(r.stage).or_insert(e);
        }
    }
    res
}

fn use_ref_or_set(val_in_rule: String, ftype: ReferableField, ref_map: &HashMap<u8, NormalizedEvent>) -> String {
    let res = if val_in_rule.starts_with(':') {
        let ref_stage = val_in_rule.strip_prefix(':').unwrap().parse::<u8>().unwrap_or_default();
        let ref_event = ref_map.get(&ref_stage).unwrap();
        match ftype {
            ReferableField::From => ref_event.src_ip.to_string(),
            ReferableField::To => ref_event.dst_ip.to_string(),
            ReferableField::PortFrom => ref_event.src_port.to_string(),
            ReferableField::PortTo => ref_event.dst_port.to_string(),
            ReferableField::Protocol => ref_event.protocol.clone().to_string(),
            ReferableField::CustomData1 => ref_event.custom_data1.clone().to_string(),
            ReferableField::CustomData2 => ref_event.custom_data2.clone().to_string(),
            ReferableField::CustomData3 => ref_event.custom_data3.clone().to_string(),
        }
    } else if val_in_rule == "ANY" || val_in_rule == "!HOME_NET" {
        match ftype {
            ReferableField::From => gen_ip().to_string(),
            ReferableField::To => gen_ip().to_string(),
            ReferableField::PortFrom => rand::random::<u16>().to_string(),
            ReferableField::PortTo => rand::random::<u16>().to_string(),
            ReferableField::Protocol => "TCP".to_string(),
            ReferableField::CustomData1 => format!("custom_data1_{}", nanoid!(5)),
            ReferableField::CustomData2 => format!("custom_data2_{}", nanoid!(5)),
            ReferableField::CustomData3 => format!("custom_data3_{}", nanoid!(5)),
        }
    } else if val_in_rule == "HOME_NET" {
        IP_IN_HOME_NET.to_string()
    } else {
        val_in_rule
    };
    res
}

enum ReferableField {
    From,
    To,
    PortFrom,
    PortTo,
    Protocol,
    CustomData1,
    CustomData2,
    CustomData3,
}

fn gen_ip() -> Ipv4Addr {
    let ip_octet = || loop {
        let n = rand::random::<u8>();
        // avoid localhost and private addresses
        if n != 0 && n != 255 && n != 10 && n != 127 && n != 192 && n != 172 {
            break n;
        }
    };
    Ipv4Addr::new(ip_octet(), ip_octet(), ip_octet(), ip_octet())
}
