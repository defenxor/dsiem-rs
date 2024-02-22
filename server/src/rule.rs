use std::{collections::HashSet, net::IpAddr, sync::Arc};

use cidr::IpCidr;
use parking_lot::RwLock;
use serde::{Deserializer, Serializer};
use serde_derive::{Deserialize, Serialize};
use tracing::warn;

use crate::{asset::NetworkAssets, event::NormalizedEvent};
use anyhow::Result;

#[derive(PartialEq, Clone, Debug, Default)]
pub enum RuleType {
    #[default]
    PluginRule,
    TaxonomyRule,
}

impl serde::Serialize for RuleType {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(match *self {
            RuleType::PluginRule => "PluginRule",
            RuleType::TaxonomyRule => "TaxonomyRule",
        })
    }
}

impl<'de> serde::Deserialize<'de> for RuleType {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        let res = match s.as_str() {
            "PluginRule" => RuleType::PluginRule,
            "TaxonomyRule" => RuleType::TaxonomyRule,
            &_ => {
                return Err(serde::de::Error::custom("invalid rule type"));
            }
        };
        Ok(res)
    }
}

#[derive(Deserialize, Serialize, Clone, Debug, Default)]
pub struct DirectiveRule {
    pub name: String,
    pub stage: u8,
    pub occurrence: usize,
    pub from: String,
    pub to: String,
    #[serde(default)]
    pub plugin_id: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub plugin_sid: Vec<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub product: Vec<String>,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub category: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub subcategory: Vec<String>,
    #[serde(rename(deserialize = "type", serialize = "type"))]
    pub rule_type: RuleType,
    pub port_from: String,
    pub port_to: String,
    pub protocol: String,
    pub reliability: u8,
    pub timeout: u32,
    #[serde(skip_serializing_if = "is_locked_zero_or_less")]
    #[serde(default)]
    pub start_time: Arc<RwLock<i64>>,
    #[serde(skip_serializing_if = "is_locked_zero_or_less")]
    #[serde(default)]
    pub end_time: Arc<RwLock<i64>>,
    #[serde(skip_serializing_if = "is_locked_string_empty")]
    #[serde(default)]
    pub status: Arc<RwLock<String>>,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub sticky_different: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub custom_data1: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub custom_label1: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub custom_data2: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub custom_label2: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub custom_data3: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    #[serde(default)]
    pub custom_label3: String,
    #[serde(skip)]
    pub sticky_diffdata: Arc<RwLock<StickyDiffData>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved_sticky_diffdata: Option<StickyDiffData>, // saveable version of sticky_diffdata
    #[serde(skip)]
    pub event_ids: Arc<RwLock<HashSet<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved_event_ids: Option<HashSet<String>>, // saveable version of event_ids
}

// This is only used for serialize
fn is_locked_zero_or_less(num: &Arc<RwLock<i64>>) -> bool {
    let r = num.read();
    *r <= 0
}
// This is only used for serialize
fn is_locked_string_empty(s: &Arc<RwLock<String>>) -> bool {
    let r = s.read();
    r.is_empty()
}

impl DirectiveRule {
    pub fn does_event_match(
        &self,
        a: &NetworkAssets,
        e: &NormalizedEvent,
        mut_sdiff: bool,
    ) -> bool {
        if self.rule_type == RuleType::PluginRule {
            plugin_rule_check(self, a, e, mut_sdiff)
        } else {
            taxonomy_rule_check(self, a, e, mut_sdiff)
        }
    }

    pub fn reset_arc_fields(mut self) -> Self {
        self.start_time = Default::default();
        self.end_time = Default::default();
        self.status = Default::default();
        self.sticky_diffdata = Default::default();
        self.event_ids = Default::default();
        self
    }
}

fn plugin_rule_check(
    r: &DirectiveRule,
    a: &NetworkAssets,
    e: &NormalizedEvent,
    mut_sdiff: bool,
) -> bool {
    if e.plugin_id != r.plugin_id {
        return false;
    }
    let mut sid_match = false;
    for v in r.plugin_sid.iter() {
        if *v == e.plugin_sid {
            sid_match = true;
            break;
        }
    }
    if !sid_match {
        return false;
    }
    if r.sticky_different == "PLUGIN_SID" {
        _ = is_int_stickydiff(e.plugin_sid, &r.sticky_diffdata, mut_sdiff);
    }
    ip_port_check(r, a, e, mut_sdiff) && custom_data_check(r, e, mut_sdiff)
}

fn taxonomy_rule_check(
    r: &DirectiveRule,
    a: &NetworkAssets,
    e: &NormalizedEvent,
    mut_sdiff: bool,
) -> bool {
    if r.category != e.category {
        return false;
    }
    let mut product_match = false;
    for v in r.product.iter() {
        if *v == e.product {
            product_match = true;
            break;
        }
    }
    if !product_match {
        return false;
    }
    // subcategory is optional and can use "ANY"
    if !r.subcategory.is_empty() {
        let mut sc_match = false;
        for v in r.subcategory.iter() {
            if *v == e.subcategory || *v == "ANY" {
                sc_match = true;
                break;
            }
        }
        if !sc_match {
            return false;
        }
    }
    ip_port_check(r, a, e, mut_sdiff)
}

fn custom_data_check(r: &DirectiveRule, e: &NormalizedEvent, mut_sdiff: bool) -> bool {
    let r1 = if !r.custom_data1.is_empty() && r.custom_data1 != "ANY" {
        match_text(&r.custom_data1, &e.custom_data1)
        // match_text_case_insensitive(&r.custom_data1, &e.custom_data1) ||
        // is_string_match_csvrule(&r.custom_data1, &e.custom_data1)
    } else {
        true
    };
    let r2 = if !r.custom_data2.is_empty() && r.custom_data2 != "ANY" {
        match_text(&r.custom_data2, &e.custom_data2)
        // match_text_case_insensitive(&r.custom_data2, &e.custom_data2) ||
        // is_string_match_csvrule(&r.custom_data2, &e.custom_data2)
    } else {
        true
    };
    let r3 = if !r.custom_data3.is_empty() && r.custom_data3 != "ANY" {
        match_text(&r.custom_data3, &e.custom_data3)
        // match_text_case_insensitive(&r.custom_data3, &e.custom_data3) ||
        // is_string_match_csvrule(&r.custom_data3, &e.custom_data3)
    } else {
        true
    };

    match r.sticky_different.as_str() {
        "CUSTOM_DATA1" => {
            _ = is_string_stickydiff(&e.custom_data1, &r.sticky_diffdata, mut_sdiff);
        }
        "CUSTOM_DATA2" => {
            _ = is_string_stickydiff(&e.custom_data2, &r.sticky_diffdata, mut_sdiff);
        }
        "CUSTOM_DATA3" => {
            _ = is_string_stickydiff(&e.custom_data3, &r.sticky_diffdata, mut_sdiff);
        }
        &_ => {}
    }

    r1 && r2 && r3
}

fn ip_port_check(
    r: &DirectiveRule,
    a: &NetworkAssets,
    e: &NormalizedEvent,
    mut_sdiff: bool,
) -> bool {
    let srcip_in_homenet = a.is_in_homenet(&e.src_ip);
    if r.from == "HOME_NET" && !srcip_in_homenet {
        return false;
    }
    if r.from == "!HOME_NET" && srcip_in_homenet {
        return false;
    }
    // covers  r.From == "IP", r.From == "IP1, IP2, !IP3", r.From == CIDR-netaddr, r.From == "CIDR1, CIDR2, !CIDR3"
    if r.from != "HOME_NET"
        && r.from != "!HOME_NET"
        && r.from != "ANY"
        && !is_ip_match_csvrule(&r.from, e.src_ip)
    {
        return false;
    }

    let dstip_in_homenet = a.is_in_homenet(&e.dst_ip);
    if r.to == "HOME_NET" && !dstip_in_homenet {
        return false;
    }
    if r.to == "!HOME_NET" && dstip_in_homenet {
        return false;
    }
    // covers  r.From == "IP", r.From == "IP1, IP2, !IP3", r.From == CIDR-netaddr, r.From == "CIDR1, CIDR2, !CIDR3"
    if r.to != "HOME_NET"
        && r.to != "!HOME_NET"
        && r.to != "ANY"
        && !is_ip_match_csvrule(&r.to, e.dst_ip)
    {
        return false;
    }

    if r.port_from != "ANY" && !is_string_match_csvrule(&r.port_from, &e.src_port.to_string()) {
        return false;
    }
    if r.port_to != "ANY" && !is_string_match_csvrule(&r.port_to, &e.dst_port.to_string()) {
        return false;
    }

    match r.sticky_different.as_str() {
        "SRC_IP" => {
            _ = is_string_stickydiff(&e.src_ip.to_string(), &r.sticky_diffdata, mut_sdiff);
        }
        "DST_IP" => {
            _ = is_string_stickydiff(&e.dst_ip.to_string(), &r.sticky_diffdata, mut_sdiff);
        }
        "SRC_PORT" => {
            _ = is_int_stickydiff(e.src_port.into(), &r.sticky_diffdata, mut_sdiff);
        }
        "DST_PORT" => {
            _ = is_int_stickydiff(e.dst_port.into(), &r.sticky_diffdata, mut_sdiff);
        }
        &_ => {}
    }

    true
}

fn match_text_case_insensitive(rule_string: &str, term: &str) -> bool {
    let mut rule_string = rule_string.to_string();
    let is_inverse = rule_string.starts_with('!');
    if is_inverse {
        rule_string.remove(0);
    }
    let m = rule_string.to_lowercase() == term.to_lowercase();
    if is_inverse {
        return !m;
    }
    m
    // m ^ is_inverse
}
fn is_string_match_csvrule(rules_in_csv: &str, term: &String) -> bool {
    let mut result = false;
    let rules: Vec<String> = rules_in_csv.split(',').map(|s| s.to_string()).collect();
    for mut v in rules {
        v = v.trim().to_owned();
        let is_inverse = v.starts_with('!');
        if is_inverse {
            v = v.replace('!', "");
        }
        let term_is_equal = v == *term;

        /*
            The correct logic here is to AND all inverse rules,
            and then OR the result with all the non-inverse rules.
            The following code implement that with shortcuts.
        */

        // break early if !condition is violated
        if is_inverse && term_is_equal {
            result = false;
            break;
        }
        // break early if condition is fulfilled
        if !is_inverse && term_is_equal {
            result = true;
            break;
        }

        // if !condition is fulfilled, continue evaluation of next in item
        if is_inverse && !term_is_equal {
            result = true;
        }
        // !isInverse && !termIsEqual should result in match = false (default)
        // so there's no need to handle it
    }
    result
}

fn is_ip_match_csvrule(rules_in_csv: &str, ip: IpAddr) -> bool {
    let mut result = false;
    let rules: Vec<String> = rules_in_csv
        .split(',')
        .map(|s| s.trim().to_string())
        .collect();
    for mut v in rules {
        let is_inverse = v.starts_with('!');
        if is_inverse {
            v = v.replace('!', "");
        }
        if !v.contains('/') {
            v += "/32";
        }
        let res = v.parse();
        if res.is_err() {
            warn!(
                "cannot parse CIDR {}: {:?}. make sure the directive is configured correctly",
                v,
                res.unwrap_err()
            );
            continue;
        }
        let ipnet_a: IpCidr = res.unwrap();
        let term_is_equal = ipnet_a.contains(&ip);

        /*
            The correct logic here is to AND all inverse rules,
            and then OR the result with all the non-inverse rules.
            The following code implement that with shortcuts.
        */

        // break early if !condition is violated
        if is_inverse && term_is_equal {
            result = false;
            break;
        }
        // break early if condition is fulfilled
        if !is_inverse && term_is_equal {
            result = true;
            break;
        }

        // if !condition is fulfilled, continue evaluation of next in item
        if is_inverse && !term_is_equal {
            result = true;
        }
        // !isInverse && !termIsEqual should result in match = false (default)
        // so there's no need to handle it
    }
    result
}

#[derive(Deserialize, Serialize, Default, Clone, Debug, PartialEq)]
pub struct StickyDiffData {
    pub sdiff_string: Vec<String>,
    pub sdiff_int: Vec<u64>,
}

// is_int_stickydiff checks if v fulfill stickydiff condition
fn is_int_stickydiff(v: u64, s: &Arc<RwLock<StickyDiffData>>, add_new: bool) -> Result<bool> {
    {
        let r_guard = s.read();
        for n in r_guard.sdiff_int.iter() {
            if *n == v {
                return Ok(false);
            }
        }
    }
    if add_new {
        let mut w_guard = s.write();
        w_guard.sdiff_int.push(v); // add it to the collection
    }
    Ok(true)
}

// is_string_stickydiff checks if v fulfill stickydiff condition
fn is_string_stickydiff(v: &str, s: &Arc<RwLock<StickyDiffData>>, add_new: bool) -> Result<bool> {
    {
        let r_guard = s.read();
        for s in r_guard.sdiff_string.iter() {
            if *s == v {
                return Ok(false);
            }
        }
    }
    if add_new {
        let mut w_guard = s.write();
        w_guard.sdiff_string.push(v.to_string());
    }
    Ok(true)
}

#[derive(Clone, Debug)]
pub struct SIDPair {
    plugin_id: u64,
    plugin_sid: Vec<u64>,
}
#[derive(Clone, Debug)]
pub struct TaxoPair {
    product: Vec<String>,
    category: String,
}

// GetQuickCheckPairs returns SIDPairs and TaxoPairs for a given set of directive rules
pub fn get_quick_check_pairs(rules: &Vec<DirectiveRule>) -> (Vec<SIDPair>, Vec<TaxoPair>) {
    let mut sid_pairs = vec![];
    let mut taxo_pairs = vec![];
    for r in rules {
        if r.plugin_id != 0 && !r.plugin_sid.is_empty() {
            sid_pairs.push(SIDPair {
                plugin_id: r.plugin_id,
                plugin_sid: r.plugin_sid.clone(),
            });
        }
        if !r.product.is_empty() && !r.category.is_empty() {
            taxo_pairs.push(TaxoPair {
                product: r.product.clone(),
                category: r.category.clone(),
            });
        }
    }
    (sid_pairs, taxo_pairs)
}

// QuickCheckTaxoRule checks event against the key fields in a directive taxonomy rules
pub fn quick_check_taxo_rule(pairs: &[TaxoPair], e: &NormalizedEvent) -> bool {
    let last = pairs
        .iter()
        .filter(|v| {
            let v = v
                .product
                .clone()
                .into_iter()
                .filter(|x| *x == e.product)
                .last();
            v.is_some()
        })
        .filter(|v| v.category == e.category)
        .last();
    last.is_some()
}

// QuickCheckPluginRule checks event against the key fields in a directive plugin rules
pub fn quick_check_plugin_rule(pairs: &[SIDPair], e: &NormalizedEvent) -> bool {
    let last = pairs
        .iter()
        .filter(|v| v.plugin_id == e.plugin_id)
        .filter(|v| {
            let v = v
                .plugin_sid
                .clone()
                .into_iter()
                .filter(|x| *x == e.plugin_sid)
                .last();
            v.is_some()
        })
        .last();
    last.is_some()
}

// WARNING: deprecated fn
// matchText match the given term against the subject, if the subject is a comma-separated-values,
// split it into slice of strings, match its value one by one, and returns if one of the value matches.
// otherwise, matchText will do non case-sensitve match for the subject and term.
fn match_text(subject: &str, term: &str) -> bool {
    if is_csv(subject) {
        return is_string_match_csvrule(subject, &term.to_string());
    }

    match_text_case_insensitive(subject, term)
}

// WARNING: deprecated fn
// isCSV determines wether the given term is a comma separated list of strings or not.
// FIXME: this is currently implemented by checking if the term contains comma character ",", which
// can cause misbehave if the term is actually a non-csv long string that contains comma character.
fn is_csv(term: &str) -> bool {
    term.contains(',')
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use super::*;
    use table_test::table_test;

    #[test]
    fn test_serde() {
        let mut r = DirectiveRule::default();
        let s = serde_json::to_string(&r).unwrap();
        let s_ref = r#"{"name":"","stage":0,"occurrence":0,"from":"","to":"","plugin_id":0,"type":"PluginRule","port_from":"","port_to":"","protocol":"","reliability":0,"timeout":0}"#;
        assert_eq!(s, s_ref);
        let r2: DirectiveRule = serde_json::from_str(s_ref).unwrap();
        assert!(r2.rule_type == RuleType::PluginRule);
        r.rule_type = RuleType::PluginRule;
        let s = serde_json::to_string(&r).unwrap();
        let s_ref = r#"{"name":"","stage":0,"occurrence":0,"from":"","to":"","plugin_id":0,"type":"PluginRule","port_from":"","port_to":"","protocol":"","reliability":0,"timeout":0}"#;
        assert_eq!(s, s_ref);
        r.rule_type = RuleType::TaxonomyRule;
        let s = serde_json::to_string(&r).unwrap();
        let s_ref = r#"{"name":"","stage":0,"occurrence":0,"from":"","to":"","plugin_id":0,"type":"TaxonomyRule","port_from":"","port_to":"","protocol":"","reliability":0,"timeout":0}"#;
        assert_eq!(s, s_ref);
    }

    #[test]
    fn test_get_quick_check_pairs() {
        let r1 = DirectiveRule {
            plugin_id: 1,
            plugin_sid: vec![1, 2, 3],
            ..Default::default()
        };

        let r2 = DirectiveRule {
            product: vec!["checkpoint".to_string()],
            category: "firewall".to_string(),
            ..Default::default()
        };
        let rules = vec![r1.clone(), r2];
        let (p, q) = get_quick_check_pairs(&rules);
        assert!(!p.is_empty());
        assert!(!q.is_empty());
        let v = p
            .into_iter()
            .filter(|v| v.plugin_id == 1 && v.plugin_sid == vec![1, 2, 3])
            .last();
        assert!(v.is_some());
        let v2 = v.clone().unwrap();
        assert_eq!(v.unwrap().plugin_id, v2.plugin_id);
        let v = q
            .into_iter()
            .filter(|v| v.product == vec!["checkpoint"] && v.category == "firewall")
            .last();
        assert!(v.is_some());
        let v2 = v.clone().unwrap();
        assert_eq!(v.unwrap().product, v2.product);
        let (_, q) = get_quick_check_pairs(&vec![r1]);
        assert!(q.is_empty());
    }
    #[test]
    fn test_quick_check_plugin_rule() {
        let pair = vec![
            SIDPair {
                plugin_id: 1,
                plugin_sid: vec![1, 2, 3],
            },
            SIDPair {
                plugin_id: 2,
                plugin_sid: vec![1, 2, 3],
            },
        ];
        let mut event = NormalizedEvent {
            plugin_id: 1,
            plugin_sid: 1,
            ..Default::default()
        };
        assert!(quick_check_plugin_rule(&pair, &event));
        event.plugin_sid = 4;
        assert!(!quick_check_plugin_rule(&pair, &event));
        event.plugin_id = 3;
        assert!(!quick_check_plugin_rule(&pair, &event))
    }
    #[test]
    fn test_quick_check_taxo_rule() {
        let pair = vec![
            TaxoPair {
                category: "firewall".to_owned(),
                product: vec!["checkpoint".to_owned(), "fortigate".to_owned()],
            },
            TaxoPair {
                category: "waf".to_owned(),
                product: vec!["f5".to_owned(), "modsec".to_owned()],
            },
        ];
        let mut event = NormalizedEvent {
            product: "checkpoint".to_owned(),
            category: "firewall".to_owned(),
            ..Default::default()
        };
        assert!(quick_check_taxo_rule(&pair, &event));
        event.category = "waf".to_string();
        assert!(!quick_check_taxo_rule(&pair, &event));
        event.product = "pf".to_string();
        assert!(!quick_check_taxo_rule(&pair, &event))
    }

    #[test]
    fn test_netaddr_in_csv() {
        let table = vec![
            (("192.168.0.1", "192.168.0.0/16"), true),
            (("192.168.0.1", "192.168.0.1"), true),
            (("192.168.0.1", "192.168.0.1/32"), true),
            (("192.168.0.1", "192.168.0.1/24"), false),
            (("192.168.0.1", "!10.0.0.0/16"), true),
            (("192.168.0.1", "!10.0.0.0/16, 192.168.0.0/24"), true),
            (("192.168.0.1", "!192.168.0.0/24"), false),
            (("192.168.0.1", "10.0.0.0/16, !192.168.0.0/16"), false),
            (
                (
                    "192.168.0.1",
                    "10.0.0.0/16, !192.168.0.0/16, 192.168.0.0/16",
                ),
                false,
            ),
        ];

        for (validator, (input_1, input_2), expected) in table_test!(table) {
            let ip = input_1.parse::<IpAddr>().unwrap();
            let actual = is_ip_match_csvrule(input_2, ip);

            validator
                .given(&format!("rules: {}, term: {}", input_2, input_1))
                .when("is_ip_match_csvrule")
                .then(&format!("it should be {}", expected))
                .assert_eq(expected, actual);
        }
    }

    #[test]
    fn test_term_in_csv() {
        let table = vec![
            (("1231", "1000, 1001"), false),
            (("1231", "!1231, 1001"), false),
            (("1231", "1000, !1231"), false),
            (("1231", "1231, !1231"), true),
            (("1231", "!1231, 1231"), false),
            (("1231", "!1000, !1001"), true),
            (("1231", "!1000, 1001"), true),
            (("1231", "1001, !1000"), true),
            (("1231", "!1000, 1231"), true),
            (("foo", "!bar, foobar, foo"), true),
        ];

        for (validator, (input_1, input_2), expected) in table_test!(table) {
            let actual = is_string_match_csvrule(input_2, &input_1.to_owned());

            validator
                .given(&format!("rules: {}, term: {}", input_2, input_1))
                .when("is_string_match_csvrule")
                .then(&format!("it should be {}", expected))
                .assert_eq(expected, actual);
        }
    }

    #[test]
    fn test_rule() {
        let asset_string = r#"{
            "assets": [
              {
                "name": "Firewall",
                "cidr": "192.168.0.1/32",
                "value": 5
              },
              {
                "name": "VulnerabilityScanner",
                "cidr": "192.168.0.2/32",
                "value": 5,
                "whitelisted": true
              },
              {
                "name": "192-168-Net",
                "cidr": "192.168.0.0/16",
                "value": 2
              },
              {
                "name": "10-Net",
                "cidr": "10.0.0.0/8",
                "value": 2
              },
              {
                "name": "172-16-Net",
                "cidr": "172.16.0.0/12",
                "value": 2
              }
            ]  
          }
          "#;
        let a = NetworkAssets::from_string(asset_string.to_owned()).unwrap();

        let r1 = DirectiveRule {
            rule_type: RuleType::PluginRule,
            plugin_id: 1001,
            plugin_sid: vec![50001],
            product: vec!["IDS".to_string()],
            category: "Malware".to_string(),
            subcategory: vec!["C&C Communication".to_string()],
            from: "HOME_NET".to_string(),
            to: "ANY".to_string(),
            port_from: "ANY".to_string(),
            port_to: "ANY".to_string(),
            protocol: "ANY".to_string(),
            ..Default::default()
        };
        let mut e1 = NormalizedEvent {
            plugin_id: 1001,
            plugin_sid: 50001,
            product: "IDS".to_string(),
            category: "Malware".to_string(),
            subcategory: "C&C Communication".to_string(),
            src_ip: IpAddr::from_str("192.168.0.1").unwrap(),
            dst_ip: IpAddr::from_str("8.8.8.200").unwrap(),
            src_port: 31337,
            dst_port: 80,
            ..Default::default()
        };

        assert!(a.is_in_homenet(&e1.src_ip));

        // plugin rule check
        let mut r2 = r1.clone();
        r2.plugin_sid = vec![50002];

        // taxonomy rule checks
        let mut r3 = r1.clone();
        r3.rule_type = RuleType::TaxonomyRule;

        let mut r4 = r3.clone();
        r4.category = "Scanning".to_string();

        let mut r5 = r1.clone();
        r5.plugin_id = 1002;

        let mut r6 = r3.clone();
        r6.product = vec!["Firewall".to_string()];

        let mut r7 = r3.clone();
        r7.subcategory = vec![];

        let mut r8 = r3.clone();
        r8.subcategory = vec!["Firewall Allow".to_string()];

        // unsupported type
        // let mut r9 = r1.clone();
        // r9.rule_type = RuleType::UnsupportedType;

        // from and to
        let mut e2 = e1.clone();
        e2.src_ip = e1.dst_ip;
        e2.dst_ip = e1.src_ip;
        let r10 = r1.clone();

        let mut r11 = r1.clone();
        r11.from = "!HOME_NET".to_string();

        let mut r12 = r1.clone();
        r12.from = "192.168.0.10".to_string();

        let mut r13 = r1.clone();
        r13.to = "HOME_NET".to_string();

        let mut e3 = e1.clone();
        e3.dst_ip = e1.src_ip;
        let mut r14 = r1.clone();
        r14.to = "!HOME_NET".to_string();

        let mut r15 = r1.clone();
        r15.to = "192.168.0.10".to_string();

        // port_from and port_to
        let mut r16 = r1.clone();
        r16.port_from = "1337".to_string();

        let mut r17 = r1.clone();
        r17.port_to = "1337".to_string();

        // rules with custom data

        let mut rc1 = r1.clone();
        rc1.custom_data1 = "deny".to_string();
        let ec1 = e1.clone();

        let rc2 = rc1.clone();
        let mut ec2 = ec1.clone();
        ec2.custom_data1 = "deny".to_string();

        let mut rc3 = rc1.clone();
        let ec3 = ec2.clone();
        rc3.custom_data2 = "malware".to_string();

        let rc4 = rc3.clone();
        let mut ec4 = ec3.clone();
        ec4.custom_data2 = "malware".to_string();

        let rc5 = rc4.clone();
        let mut ec5 = ec4.clone();
        ec5.custom_data2 = "exploit".to_string();

        let mut rc6 = rc5.clone();
        let ec6 = ec5.clone();
        rc6.custom_data3 = "7000".to_string();

        let rc7 = rc6.clone();
        let mut ec7 = ec6.clone();
        ec7.custom_data3 = "7000".to_string();

        let rc8 = rc7.clone();
        let mut ec8 = ec7.clone();
        ec8.custom_data2 = "malware".to_string();

        let mut rc9 = rc8.clone();
        let ec9 = ec8.clone();
        rc9.custom_data2 = "!malware".to_string();

        // StickyDiff rules
        // TODO: add the appropriate test that test the length of stickyDiffData
        // before and after

        let mut rs1 = r1.clone();
        rs1.sticky_different = "PLUGIN_SID".to_string();
        let s1 = StickyDiffData {
            sdiff_int: vec![50001],
            ..Default::default()
        };

        let s2 = s1.clone();
        let rs2 = rs1.clone();

        let s3 = StickyDiffData {
            sdiff_int: vec![50001],
            sdiff_string: vec!["192.168.0.1".to_string()],
        };
        let mut rs3 = rs1.clone();
        rs3.sticky_different = "SRC_IP".to_string();

        let mut s4 = s3.clone();
        s4.sdiff_string.push("8.8.8.200".to_string());
        let mut rs4 = rs1.clone();
        rs4.sticky_different = "DST_IP".to_string();

        let s8 = StickyDiffData {
            sdiff_int: vec![31337],
            ..Default::default()
        };
        let mut rs8 = r1.clone().reset_arc_fields();
        rs8.sticky_different = "SRC_PORT".to_string();

        let mut s9 = s8.clone();
        s9.sdiff_int.push(80);
        let mut rs9 = rs8.clone();
        rs9.sticky_different = "DST_PORT".to_string();

        let s10 = StickyDiffData {
            sdiff_string: vec!["foo".to_string()],
            ..Default::default()
        };
        let mut rs10 = r1.clone().reset_arc_fields();
        rs10.custom_data1 = "foo".to_string();
        e1.custom_data1 = "foo".to_string();
        rs10.sticky_different = "CUSTOM_DATA1".to_string();

        let mut s11 = s10.clone();
        s11.sdiff_string.push("bar".to_string());
        let mut rs11 = rs10.clone();
        rs11.custom_data2 = "bar".to_string();
        e1.custom_data2 = "bar".to_string();
        rs11.sticky_different = "CUSTOM_DATA2".to_string();

        let mut s12 = s11.clone();
        let mut rs12 = rs11.clone();
        s12.sdiff_string.push("baz".to_string());
        rs12.custom_data3 = "baz".to_string();
        e1.custom_data3 = "baz".to_string();
        rs12.sticky_different = "CUSTOM_DATA3".to_string();

        let s13 = s12.clone();
        let mut rs13 = rs12.clone();
        rs13.custom_data3 = "qux".to_string();
        rs13.sticky_different = "CUSTOM_DATA3".to_string();

        // custom_data1 test
        let mut rany1 = r1.clone();
        rany1.custom_data1 = "ANY".to_string();

        let mut rany2 = rany1.clone();
        rany2.custom_data1 = "".to_string();

        let mut rany3 = rany1.clone();
        rany3.custom_data1 = "quas".to_string();

        let mut rany4 = rany1.clone();
        rany4.custom_data1 = "foo".to_string();

        // custom_data2 test
        let mut rany5 = r1.clone();
        rany5.custom_data2 = "ANY".to_string();

        let mut rany6 = rany5.clone();
        rany6.custom_data2 = "".to_string();

        let mut rany7 = rany5.clone();
        rany7.custom_data2 = "quas".to_string();

        let mut rany8 = rany5.clone();
        rany8.custom_data2 = "bar".to_string();

        // custom_data3 test
        let mut rany9 = r1.clone();
        rany9.custom_data3 = "ANY".to_string();

        let mut rany10 = rany9.clone();
        rany10.custom_data3 = "".to_string();

        let mut rany11 = rany9.clone();
        rany11.custom_data3 = "quas".to_string();

        let mut rany12 = rany9.clone();
        rany12.custom_data3 = "qux".to_string();

        let mut eany1 = e1.clone();
        eany1.custom_data1 = "foo".to_string();
        eany1.custom_data2 = "bar".to_string();
        eany1.custom_data3 = "qux".to_string();

        let mut eany2 = eany1.clone();
        eany2.custom_data1 = "".to_string();
        eany2.custom_data2 = "".to_string();
        eany2.custom_data3 = "".to_string();

        let table = vec![
            ((1, e1.clone(), r1), true),
            ((2, e1.clone(), r2), false),
            ((3, e1.clone(), r3), true),
            ((4, e1.clone(), r4), false),
            ((5, e1.clone(), r5), false),
            ((6, e1.clone(), r6), false),
            ((7, e1.clone(), r7), true),
            ((8, e1.clone(), r8), false),
            // ((9, e1.clone(), r9), false),
            ((10, e2, r10), false),
            ((11, e1.clone(), r11), false),
            ((12, e1.clone(), r12), false),
            ((13, e1.clone(), r13), false),
            ((14, e3, r14), false),
            ((15, e1.clone(), r15), false),
            ((16, e1.clone(), r16), false),
            ((17, e1.clone(), r17), false),
            ((51, ec1, rc1), false),
            ((52, ec2, rc2), true),
            ((53, ec3, rc3), false),
            ((54, ec4, rc4), true),
            ((55, ec5, rc5), false),
            ((56, ec6, rc6), false),
            ((57, ec7, rc7), false),
            ((58, ec8, rc8), true),
            ((59, ec9, rc9), false),
            ((113, eany1.clone(), rany1.clone()), true),
            ((114, eany1.clone(), rany2.clone()), true),
            ((115, eany1.clone(), rany3.clone()), false),
            ((116, eany1.clone(), rany4.clone()), true),
            ((117, eany1.clone(), rany5.clone()), true),
            ((118, eany1.clone(), rany6.clone()), true),
            ((119, eany1.clone(), rany7.clone()), false),
            ((120, eany1.clone(), rany8.clone()), true),
            ((121, eany1.clone(), rany9.clone()), true),
            ((122, eany1.clone(), rany10.clone()), true),
            ((123, eany1.clone(), rany11.clone()), false),
            ((124, eany1, rany12.clone()), true),
            ((125, eany2.clone(), rany1), true),
            ((126, eany2.clone(), rany2), true),
            ((127, eany2.clone(), rany3), false),
            ((128, eany2.clone(), rany4), false),
            ((129, eany2.clone(), rany5), true),
            ((130, eany2.clone(), rany6), true),
            ((131, eany2.clone(), rany7), false),
            ((132, eany2.clone(), rany8), false),
            ((133, eany2.clone(), rany9), true),
            ((134, eany2.clone(), rany10), true),
            ((135, eany2.clone(), rany11), false),
            ((136, eany2, rany12), false),
        ];

        for (validator, (case_id, event, rule), expected) in table_test!(table) {
            let actual = rule.does_event_match(&a, &event, false);

            validator
                .given(&format!("test_case: {}, ", case_id))
                .when("does_event_match")
                .then(&format!("it should be {}", expected))
                .assert_eq(expected, actual);
        }

        let table_stickydiff = vec![
            ((101, e1.clone(), rs1, s1), true),
            ((102, e1.clone(), rs2, s2), true),
            ((103, e1.clone(), rs3, s3), true),
            ((104, e1.clone(), rs4, s4), true),
            ((108, e1.clone(), rs8, s8), true),
            ((109, e1.clone(), rs9, s9), true),
            ((110, e1.clone(), rs10, s10), true),
            ((111, e1.clone(), rs11, s11), true),
            ((112, e1.clone(), rs12, s12), true),
            ((113, e1, rs13, s13), false),
        ];

        for (validator, (case_id, event, rule, sticky_diff), expected) in
            table_test!(table_stickydiff)
        {
            let actual = rule.does_event_match(&a, &event, true);
            let sticky_diff_actual: StickyDiffData;
            {
                let r = rule.sticky_diffdata.read();
                sticky_diff_actual = r.to_owned();
            }

            validator
                .given(&format!("test_case: {}, ", case_id))
                .when("does_event_match")
                .then(&format!("it should be {}", expected))
                .assert_eq(expected, actual)
                .then(&format!("stickydiff should be {:?}", sticky_diff))
                .assert_eq(sticky_diff, sticky_diff_actual);
        }
    }

    #[test]
    fn test_custom_data_match() {
        let table = vec![
            ((1, "Network Command Shell", "Network Command Shell"), true),
            ((2, "Network Command Shell", "Network Command Login"), false),
            (
                (3, "!Network Command Shell", "Network Command Shell"),
                false,
            ),
            ((4, "!Network Command Shell", "Network Command Login"), true),
            ((5, "foo,bar,qux", "foo"), true),
            ((6, "foo,bar,qux", "bar"), true),
            ((7, "foo,bar,qux", "qux"), true),
            ((8, "foo,bar,qux", "baz"), false),
            ((9, "foo,!bar,qux", "bar"), false),
            ((10, "foo,bar,!qux", "qux"), false),
            ((11, "!foo,bar,qux", "foo"), false),
            ((12, "!foo, foo, bar, qux", "foo"), false),
            ((13, "foo, !foo, bar, qux", "foo"), true),
        ];

        let mut r = DirectiveRule {
            rule_type: RuleType::PluginRule,
            plugin_id: 1001,
            plugin_sid: vec![50001],
            from: "ANY".to_string(),
            to: "ANY".to_string(),
            port_from: "ANY".to_string(),
            port_to: "ANY".to_string(),
            protocol: "ANY".to_string(),
            ..Default::default()
        };
        let mut e = NormalizedEvent {
            plugin_id: 1001,
            plugin_sid: 50001,
            src_ip: IpAddr::from_str("192.168.0.1").unwrap(),
            dst_ip: IpAddr::from_str("8.8.8.200").unwrap(),
            src_port: 31337,
            dst_port: 80,
            ..Default::default()
        };

        let a = NetworkAssets::from_string(r#"{ "assets": [] }"#.to_string()).unwrap();
        for (validator, (case_id, rule_customdata, event_customdata), expected) in
            table_test!(table)
        {
            r.custom_data1 = rule_customdata.to_string();
            e.custom_data1 = event_customdata.to_string();
            let actual = r.does_event_match(&a, &e, true);

            validator
                .given(&format!("test_case: {}, ", case_id))
                .when("does_event_match")
                .then(&format!("it should be {}", expected))
                .assert_eq(expected, actual);
        }
    }
}
