use std::{
    collections::HashSet,
    net::IpAddr,
    sync::{atomic::AtomicBool, Arc},
};

use anyhow::Result;
use arcstr::ArcStr;
use cidr::IpCidr;
use parking_lot::Mutex;
use serde::{Deserializer, Serializer};
use serde_derive::{Deserialize, Serialize};
use tracing::warn;

use crate::{asset::NetworkAssets, event::NormalizedEvent, utils::ref_to_digit};

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
    pub from: ArcStr,
    pub to: ArcStr,
    #[serde(default)]
    pub plugin_id: u64,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub plugin_sid: Vec<u64>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub product: Vec<ArcStr>,
    #[serde(skip_serializing_if = "ArcStr::is_empty")]
    #[serde(default)]
    pub category: ArcStr,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    #[serde(default)]
    pub subcategory: Vec<ArcStr>,
    #[serde(rename(deserialize = "type", serialize = "type"))]
    pub rule_type: RuleType,
    pub port_from: ArcStr,
    pub port_to: ArcStr,
    pub protocol: ArcStr,
    pub reliability: u8,
    pub timeout: u32,
    #[serde(skip_serializing_if = "is_locked_zero_or_less")]
    #[serde(default)]
    pub start_time: Arc<Mutex<i64>>,
    #[serde(skip_serializing_if = "is_locked_zero_or_less")]
    #[serde(default)]
    pub end_time: Arc<Mutex<i64>>,
    #[serde(skip_serializing_if = "is_locked_string_empty")]
    #[serde(default)]
    pub status: Arc<Mutex<ArcStr>>,
    #[serde(skip_serializing_if = "ArcStr::is_empty")]
    #[serde(default)]
    pub sticky_different: ArcStr,
    #[serde(skip_serializing_if = "ArcStr::is_empty")]
    #[serde(default)]
    pub custom_data1: ArcStr,
    #[serde(skip_serializing_if = "ArcStr::is_empty")]
    #[serde(default)]
    pub custom_label1: ArcStr,
    #[serde(skip_serializing_if = "ArcStr::is_empty")]
    #[serde(default)]
    pub custom_data2: ArcStr,
    #[serde(skip_serializing_if = "ArcStr::is_empty")]
    #[serde(default)]
    pub custom_label2: ArcStr,
    #[serde(skip_serializing_if = "ArcStr::is_empty")]
    #[serde(default)]
    pub custom_data3: ArcStr,
    #[serde(skip_serializing_if = "ArcStr::is_empty")]
    #[serde(default)]
    pub custom_label3: ArcStr,
    #[serde(skip)]
    pub sticky_diffdata: Arc<Mutex<StickyDiffData>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved_sticky_diffdata: Option<StickyDiffData>, // saveable version of sticky_diffdata
    #[serde(skip)]
    pub event_ids: Arc<Mutex<HashSet<String>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub saved_event_ids: Option<HashSet<String>>, // saveable version of event_ids
    #[serde(skip)]
    first_event: Arc<Mutex<NormalizedEvent>>,
    #[serde(skip)]
    first_event_set_flag: Arc<AtomicBool>,
}

// This is only used for serialize
fn is_locked_zero_or_less(num: &Arc<Mutex<i64>>) -> bool {
    let r = num.lock();
    *r <= 0
}
// This is only used for serialize
fn is_locked_string_empty(s: &Arc<Mutex<ArcStr>>) -> bool {
    let r = s.lock();
    r.is_empty()
}

impl DirectiveRule {
    pub fn set_first_event(&self, e: NormalizedEvent) -> Result<()> {
        if self.is_first_event_set() {
            return Err(anyhow::anyhow!("first event is already set"));
        };
        let mut w = self.first_event.lock();
        *w = e;
        Ok(())
    }
    pub fn is_first_event_set(&self) -> bool {
        self.first_event_set_flag.load(std::sync::atomic::Ordering::Relaxed)
    }

    pub fn does_event_match(
        &self,
        a: &NetworkAssets,
        e: &NormalizedEvent,
        rules: &[DirectiveRule],
        mut_sdiff: bool,
    ) -> bool {
        if self.protocol != "ANY" && !self.protocol.is_empty() && self.protocol != e.protocol {
            return false;
        }
        if self.rule_type == RuleType::PluginRule {
            plugin_rule_check(self, a, e, rules, mut_sdiff)
        } else {
            taxonomy_rule_check(self, a, e, rules, mut_sdiff)
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

fn ref_check(r: &DirectiveRule, e: &NormalizedEvent, rules: &[DirectiveRule]) -> bool {
    // if any reference pointed by one of these doesn't match the event, return
    // false
    if let Some(v) = ref_to_digit(&r.from) {
        if rules[usize::from(v - 1)].first_event.lock().src_ip != e.src_ip {
            return false;
        }
    }
    if let Some(v) = ref_to_digit(&r.to) {
        if rules[usize::from(v - 1)].first_event.lock().dst_ip != e.dst_ip {
            return false;
        }
    }
    if let Some(v) = ref_to_digit(&r.port_from) {
        if rules[usize::from(v - 1)].first_event.lock().src_port != e.src_port {
            return false;
        }
    }
    if let Some(v) = ref_to_digit(&r.port_to) {
        if rules[usize::from(v - 1)].first_event.lock().dst_port != e.dst_port {
            return false;
        }
    }
    if let Some(v) = ref_to_digit(&r.protocol) {
        if rules[usize::from(v - 1)].first_event.lock().protocol != e.protocol {
            return false;
        }
    }
    if let Some(v) = ref_to_digit(&r.custom_data1) {
        if rules[usize::from(v - 1)].first_event.lock().custom_data1 != e.custom_data1 {
            return false;
        }
    }
    if let Some(v) = ref_to_digit(&r.custom_data2) {
        if rules[usize::from(v - 1)].first_event.lock().custom_data2 != e.custom_data2 {
            return false;
        }
    }
    if let Some(v) = ref_to_digit(&r.custom_data3) {
        if rules[usize::from(v - 1)].first_event.lock().custom_data3 != e.custom_data3 {
            return false;
        }
    }
    true
}

fn plugin_rule_check(
    r: &DirectiveRule,
    a: &NetworkAssets,
    e: &NormalizedEvent,
    rules: &[DirectiveRule],
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
    ip_port_check(r, a, e, mut_sdiff) && ref_check(r, e, rules) && custom_data_check(r, e, mut_sdiff)
}

fn taxonomy_rule_check(
    r: &DirectiveRule,
    a: &NetworkAssets,
    e: &NormalizedEvent,
    rules: &[DirectiveRule],
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
    ip_port_check(r, a, e, mut_sdiff) && ref_check(r, e, rules) && custom_data_check(r, e, mut_sdiff)
}

fn custom_data_check(r: &DirectiveRule, e: &NormalizedEvent, mut_sdiff: bool) -> bool {
    // this only handles the case where the custom data is a specific string and
    // empty, ANY, or reference to other rule

    let r1 = if !r.custom_data1.is_empty() && r.custom_data1 != "ANY" && ref_to_digit(&r.custom_data1).is_none() {
        match_text(&r.custom_data1, &e.custom_data1)
        // match_text_case_insensitive(&r.custom_data1, &e.custom_data1) ||
        // is_string_match_csvrule(&r.custom_data1, &e.custom_data1)
    } else {
        true
    };
    let r2 = if !r.custom_data2.is_empty() && r.custom_data2 != "ANY" && ref_to_digit(&r.custom_data2).is_none() {
        match_text(&r.custom_data2, &e.custom_data2)
        // match_text_case_insensitive(&r.custom_data2, &e.custom_data2) ||
        // is_string_match_csvrule(&r.custom_data2, &e.custom_data2)
    } else {
        true
    };
    let r3 = if !r.custom_data3.is_empty() && r.custom_data3 != "ANY" && ref_to_digit(&r.custom_data3).is_none() {
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

fn ip_port_check(r: &DirectiveRule, a: &NetworkAssets, e: &NormalizedEvent, mut_sdiff: bool) -> bool {
    let srcip_in_homenet = a.is_in_homenet(&e.src_ip);
    if r.from == "HOME_NET" && !srcip_in_homenet {
        return false;
    }
    if r.from == "!HOME_NET" && srcip_in_homenet {
        return false;
    }
    // covers  r.From == "IP", r.From == "IP1, IP2, !IP3", r.From == CIDR-netaddr,
    // r.From == "CIDR1, CIDR2, !CIDR3"
    if r.from != "HOME_NET"
        && r.from != "!HOME_NET"
        && r.from != "ANY"
        && ref_to_digit(&r.from).is_none()
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
    // covers  r.From == "IP", r.From == "IP1, IP2, !IP3", r.From == CIDR-netaddr,
    // r.From == "CIDR1, CIDR2, !CIDR3"
    if r.to != "HOME_NET"
        && r.to != "!HOME_NET"
        && r.to != "ANY"
        && ref_to_digit(&r.to).is_none()
        && !is_ip_match_csvrule(&r.to, e.dst_ip)
    {
        return false;
    }

    if r.port_from != "ANY"
        && ref_to_digit(&r.port_from).is_none()
        && !is_string_match_csvrule(&r.port_from, &e.src_port.to_string())
    {
        return false;
    }
    if r.port_to != "ANY"
        && ref_to_digit(&r.port_to).is_none()
        && !is_string_match_csvrule(&r.port_to, &e.dst_port.to_string())
    {
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
    let rules: Vec<String> = rules_in_csv.split(',').map(|s| s.trim().to_string()).collect();
    for mut v in rules {
        let is_inverse = v.starts_with('!');
        if is_inverse {
            v = v.replace('!', "");
        }
        if !v.contains('/') {
            match ip {
                IpAddr::V4(_) => {
                    v += "/32";
                }
                IpAddr::V6(_) => {
                    v += "/128";
                }
            }
        };
        let res = v.parse();
        if res.is_err() {
            warn!("cannot parse CIDR {}: {:?}. make sure the directive is configured correctly", v, res.unwrap_err());
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
fn is_int_stickydiff(v: u64, s: &Arc<Mutex<StickyDiffData>>, add_new: bool) -> Result<bool> {
    {
        let r_guard = s.lock();
        for n in r_guard.sdiff_int.iter() {
            if *n == v {
                return Ok(false);
            }
        }
    }
    if add_new {
        let mut w_guard = s.lock();
        w_guard.sdiff_int.push(v); // add it to the collection
    }
    Ok(true)
}

// is_string_stickydiff checks if v fulfill stickydiff condition
fn is_string_stickydiff(v: &str, s: &Arc<Mutex<StickyDiffData>>, add_new: bool) -> Result<bool> {
    {
        let r_guard = s.lock();
        for s in r_guard.sdiff_string.iter() {
            if *s == v {
                return Ok(false);
            }
        }
    }
    if add_new {
        let mut w_guard = s.lock();
        w_guard.sdiff_string.push(v.to_string());
    }
    Ok(true)
}

#[derive(Clone, Debug)]
pub struct SIDPair {
    pub plugin_id: u64,
    pub plugin_sid: Vec<u64>,
}
#[derive(Clone, Debug)]
pub struct TaxoPair {
    pub product: Vec<ArcStr>,
    pub category: ArcStr,
}

// GetQuickCheckPairs returns SIDPairs and TaxoPairs for a given set of
// directive rules
pub fn get_quick_check_pairs(rules: &[DirectiveRule]) -> (Vec<SIDPair>, Vec<TaxoPair>) {
    let mut sid_pairs = vec![];
    let mut taxo_pairs = vec![];
    for r in rules {
        if r.plugin_id != 0 && !r.plugin_sid.is_empty() {
            sid_pairs.push(SIDPair { plugin_id: r.plugin_id, plugin_sid: r.plugin_sid.clone() });
        }
        if !r.product.is_empty() && !r.category.is_empty() {
            taxo_pairs.push(TaxoPair { product: r.product.clone(), category: r.category.clone() });
        }
    }
    (sid_pairs, taxo_pairs)
}

#[inline(always)]
pub fn quick_check_taxo_rule(pairs: &[TaxoPair], e: &NormalizedEvent) -> bool {
    pairs.iter().filter(|v| v.product.iter().any(|x| *x == e.product)).any(|v| v.category == e.category)
}

// QuickCheckPluginRule checks event against the key fields in a directive
// plugin rules
#[inline(always)]
pub fn quick_check_plugin_rule(pairs: &[SIDPair], e: &NormalizedEvent) -> bool {
    pairs.iter().filter(|v| v.plugin_id == e.plugin_id).any(|v| v.plugin_sid.iter().any(|x| *x == e.plugin_sid))
}

// WARNING: deprecated fn
// matchText match the given term against the subject, if the subject is a
// comma-separated-values, split it into slice of strings, match its value one
// by one, and returns if one of the value matches. otherwise, matchText will do
// non case-sensitive match for the subject and term.
fn match_text(subject: &str, term: &str) -> bool {
    if is_csv(subject) {
        return is_string_match_csvrule(subject, &term.to_string());
    }

    match_text_case_insensitive(subject, term)
}

// WARNING: deprecated fn
// isCSV determines wether the given term is a comma separated list of strings
// or not. FIXME: this is currently implemented by checking if the term contains
// comma character ",", which can cause misbehave if the term is actually a
// non-csv long string that contains comma character.
fn is_csv(term: &str) -> bool {
    term.contains(',')
}

#[cfg(test)]
mod test {
    use std::str::FromStr;

    use table_test::table_test;

    use super::*;

    #[test]
    fn test_serde() {
        let pretty_literal_xd = |s: &str| -> String { s.replace(&" ".repeat(8), "").replace(&" ".repeat(4), "  ") };

        let mut r = DirectiveRule::default();
        let s = serde_json::to_string_pretty(&r).unwrap();
        let s_ref = pretty_literal_xd(
            r#"{
            "name": "",
            "stage": 0,
            "occurrence": 0,
            "from": "",
            "to": "",
            "plugin_id": 0,
            "type": "PluginRule",
            "port_from": "",
            "port_to": "",
            "protocol": "",
            "reliability": 0,
            "timeout": 0
        }"#,
        );
        let s_ref = s_ref.as_str();
        assert_eq!(s, s_ref);
        let r2: DirectiveRule = serde_json::from_str(s_ref).unwrap();
        assert!(r2.rule_type == RuleType::PluginRule);

        r.rule_type = RuleType::PluginRule;
        let s = serde_json::to_string_pretty(&r).unwrap();
        let s_ref = pretty_literal_xd(
            r#"{
            "name": "",
            "stage": 0,
            "occurrence": 0,
            "from": "",
            "to": "",
            "plugin_id": 0,
            "type": "PluginRule",
            "port_from": "",
            "port_to": "",
            "protocol": "",
            "reliability": 0,
            "timeout": 0
        }"#,
        );
        assert_eq!(s, s_ref);

        r.rule_type = RuleType::TaxonomyRule;
        let s = serde_json::to_string_pretty(&r).unwrap();
        let s_ref = pretty_literal_xd(
            r#"{
            "name": "",
            "stage": 0,
            "occurrence": 0,
            "from": "",
            "to": "",
            "plugin_id": 0,
            "type": "TaxonomyRule",
            "port_from": "",
            "port_to": "",
            "protocol": "",
            "reliability": 0,
            "timeout": 0
        }"#,
        );
        assert_eq!(s, s_ref);
    }

    #[test]
    fn test_get_quick_check_pairs() {
        let r1 = DirectiveRule { plugin_id: 1, plugin_sid: vec![1, 2, 3], ..Default::default() };

        let r2 =
            DirectiveRule { product: vec!["checkpoint".into()], category: "firewall".into(), ..Default::default() };
        let rules = vec![r1.clone(), r2];
        let (p, q) = get_quick_check_pairs(&rules);
        assert!(!p.is_empty());
        assert!(!q.is_empty());
        let v = p.into_iter().filter(|v| v.plugin_id == 1 && v.plugin_sid == vec![1, 2, 3]).last();
        assert!(v.is_some());
        let v2 = v.clone().unwrap();
        assert_eq!(v.unwrap().plugin_id, v2.plugin_id);
        let v = q.into_iter().filter(|v| v.product == vec!["checkpoint"] && v.category == "firewall").last();
        assert!(v.is_some());
        let v2 = v.clone().unwrap();
        assert_eq!(v.unwrap().product, v2.product);
        let (_, q) = get_quick_check_pairs(&vec![r1]);
        assert!(q.is_empty());
    }
    #[test]
    fn test_quick_check_plugin_rule() {
        let pair = vec![SIDPair { plugin_id: 1, plugin_sid: vec![1, 2, 3] }, SIDPair {
            plugin_id: 2,
            plugin_sid: vec![1, 2, 3],
        }];
        let mut event = NormalizedEvent { plugin_id: 1, plugin_sid: 1, ..Default::default() };
        assert!(quick_check_plugin_rule(&pair, &event));
        event.plugin_sid = 4;
        assert!(!quick_check_plugin_rule(&pair, &event));
        event.plugin_id = 3;
        assert!(!quick_check_plugin_rule(&pair, &event))
    }
    #[test]
    fn test_quick_check_taxo_rule() {
        let pair = vec![
            TaxoPair { category: "firewall".into(), product: vec!["checkpoint".into(), "fortigate".into()] },
            TaxoPair { category: "waf".into(), product: vec!["f5".into(), "modsec".into()] },
        ];
        let mut event =
            NormalizedEvent { product: "checkpoint".into(), category: "firewall".into(), ..Default::default() };
        assert!(quick_check_taxo_rule(&pair, &event));
        event.category = "waf".into();
        assert!(!quick_check_taxo_rule(&pair, &event));
        event.product = "pf".into();
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
            (("192.168.0.1", "10.0.0.0/16, !192.168.0.0/16, 192.168.0.0/16"), false),
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
            product: vec!["IDS".into()],
            category: "Malware".into(),
            subcategory: vec!["C&C Communication".into()],
            from: "HOME_NET".into(),
            to: "ANY".into(),
            port_from: "ANY".into(),
            port_to: "ANY".into(),
            protocol: "ANY".into(),
            ..Default::default()
        };
        let mut e1 = NormalizedEvent {
            plugin_id: 1001,
            plugin_sid: 50001,
            product: "IDS".into(),
            category: "Malware".into(),
            subcategory: "C&C Communication".into(),
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
        r4.category = "Scanning".into();

        let mut r5 = r1.clone();
        r5.plugin_id = 1002;

        let mut r6 = r3.clone();
        r6.product = vec!["Firewall".into()];

        let mut r7 = r3.clone();
        r7.subcategory = vec![];

        let mut r8 = r3.clone();
        r8.subcategory = vec!["Firewall Allow".into()];

        // unsupported type
        // let mut r9 = r1.clone();
        // r9.rule_type = RuleType::UnsupportedType;

        // from and to
        let mut e2 = e1.clone();
        e2.src_ip = e1.dst_ip;
        e2.dst_ip = e1.src_ip;
        let r10 = r1.clone();

        let mut r11 = r1.clone();
        r11.from = "!HOME_NET".into();

        let mut r12 = r1.clone();
        r12.from = "192.168.0.10".into();

        let mut r13 = r1.clone();
        r13.to = "HOME_NET".into();

        let mut e3 = e1.clone();
        e3.dst_ip = e1.src_ip;
        let mut r14 = r1.clone();
        r14.to = "!HOME_NET".into();

        let mut r15 = r1.clone();
        r15.to = "192.168.0.10".into();

        // port_from and port_to
        let mut r16 = r1.clone();
        r16.port_from = "1337".into();

        let mut r17 = r1.clone();
        r17.port_to = "1337".into();

        // rules with custom data

        let mut rc1 = r1.clone();
        rc1.custom_data1 = "deny".into();
        let ec1 = e1.clone();

        let rc2 = rc1.clone();
        let mut ec2 = ec1.clone();
        ec2.custom_data1 = "deny".into();

        let mut rc3 = rc1.clone();
        let ec3 = ec2.clone();
        rc3.custom_data2 = "malware".into();

        let rc4 = rc3.clone();
        let mut ec4 = ec3.clone();
        ec4.custom_data2 = "malware".into();

        let rc5 = rc4.clone();
        let mut ec5 = ec4.clone();
        ec5.custom_data2 = "exploit".into();

        let mut rc6 = rc5.clone();
        let ec6 = ec5.clone();
        rc6.custom_data3 = "7000".into();

        let rc7 = rc6.clone();
        let mut ec7 = ec6.clone();
        ec7.custom_data3 = "7000".into();

        let rc8 = rc7.clone();
        let mut ec8 = ec7.clone();
        ec8.custom_data2 = "malware".into();

        let mut rc9 = rc8.clone();
        let ec9 = ec8.clone();
        rc9.custom_data2 = "!malware".into();

        // StickyDiff rules
        // TODO: add the appropriate test that test the length of stickyDiffData
        // before and after

        let mut rs1 = r1.clone();
        rs1.sticky_different = "PLUGIN_SID".into();
        let s1 = StickyDiffData { sdiff_int: vec![50001], ..Default::default() };

        let s2 = s1.clone();
        let rs2 = rs1.clone();

        let s3 = StickyDiffData { sdiff_int: vec![50001], sdiff_string: vec!["192.168.0.1".to_string()] };
        let mut rs3 = rs1.clone();
        rs3.sticky_different = "SRC_IP".into();

        let mut s4 = s3.clone();
        s4.sdiff_string.push("8.8.8.200".to_string());
        let mut rs4 = rs1.clone();
        rs4.sticky_different = "DST_IP".into();

        let s8 = StickyDiffData { sdiff_int: vec![31337], ..Default::default() };
        let mut rs8 = r1.clone().reset_arc_fields();
        rs8.sticky_different = "SRC_PORT".into();

        let mut s9 = s8.clone();
        s9.sdiff_int.push(80);
        let mut rs9 = rs8.clone();
        rs9.sticky_different = "DST_PORT".into();

        let s10 = StickyDiffData { sdiff_string: vec!["foo".into()], ..Default::default() };
        let mut rs10 = r1.clone().reset_arc_fields();
        rs10.custom_data1 = "foo".into();
        e1.custom_data1 = "foo".into();
        rs10.sticky_different = "CUSTOM_DATA1".into();

        let mut s11 = s10.clone();
        s11.sdiff_string.push("bar".to_string());
        let mut rs11 = rs10.clone();
        rs11.custom_data2 = "bar".into();
        e1.custom_data2 = "bar".into();
        rs11.sticky_different = "CUSTOM_DATA2".into();

        let mut s12 = s11.clone();
        let mut rs12 = rs11.clone();
        s12.sdiff_string.push("baz".into());
        rs12.custom_data3 = "baz".into();
        e1.custom_data3 = "baz".into();
        rs12.sticky_different = "CUSTOM_DATA3".into();

        let s13 = s12.clone();
        let mut rs13 = rs12.clone();
        rs13.custom_data3 = "qux".into();
        rs13.sticky_different = "CUSTOM_DATA3".into();

        // custom_data1 test
        let mut rany1 = r1.clone();
        rany1.custom_data1 = "ANY".into();

        let mut rany2 = rany1.clone();
        rany2.custom_data1 = "".into();

        let mut rany3 = rany1.clone();
        rany3.custom_data1 = "quas".into();

        let mut rany4 = rany1.clone();
        rany4.custom_data1 = "foo".into();

        // custom_data2 test
        let mut rany5 = r1.clone();
        rany5.custom_data2 = "ANY".into();

        let mut rany6 = rany5.clone();
        rany6.custom_data2 = "".into();

        let mut rany7 = rany5.clone();
        rany7.custom_data2 = "quas".into();

        let mut rany8 = rany5.clone();
        rany8.custom_data2 = "bar".into();

        // custom_data3 test
        let mut rany9 = r1.clone();
        rany9.custom_data3 = "ANY".into();

        let mut rany10 = rany9.clone();
        rany10.custom_data3 = "".into();

        let mut rany11 = rany9.clone();
        rany11.custom_data3 = "quas".into();

        let mut rany12 = rany9.clone();
        rany12.custom_data3 = "qux".into();

        let mut eany1 = e1.clone();
        eany1.custom_data1 = "foo".into();
        eany1.custom_data2 = "bar".into();
        eany1.custom_data3 = "qux".into();

        let mut eany2 = eany1.clone();
        eany2.custom_data1 = "".into();
        eany2.custom_data2 = "".into();
        eany2.custom_data3 = "".into();

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

        let rules = vec![]; // references aren't checked here

        for (validator, (case_id, event, rule), expected) in table_test!(table) {
            let actual = rule.does_event_match(&a, &event, &rules, false);

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

        let rules = vec![]; // references aren't checked here

        for (validator, (case_id, event, rule, sticky_diff), expected) in table_test!(table_stickydiff) {
            let actual = rule.does_event_match(&a, &event, &rules, true);
            let sticky_diff_actual: StickyDiffData;
            {
                let r = rule.sticky_diffdata.lock();
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
            ((3, "!Network Command Shell", "Network Command Shell"), false),
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
            from: "ANY".into(),
            to: "ANY".into(),
            port_from: "ANY".into(),
            port_to: "ANY".into(),
            protocol: "ANY".into(),
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

        let rules = vec![]; // references aren't checked here

        let a = NetworkAssets::from_string(r#"{ "assets": [] }"#.to_string()).unwrap();
        for (validator, (case_id, rule_customdata, event_customdata), expected) in table_test!(table) {
            r.custom_data1 = rule_customdata.into();
            e.custom_data1 = event_customdata.into();
            let actual = r.does_event_match(&a, &e, &rules, true);

            validator
                .given(&format!("test_case: {}, ", case_id))
                .when("does_event_match")
                .then(&format!("it should be {}", expected))
                .assert_eq(expected, actual);
        }
    }
}
