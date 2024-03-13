use parking_lot::Mutex;
use regex::Regex;
use serde_derive::Deserialize;
use std::{fs, str::FromStr, sync::Arc};
extern crate glob;
use anyhow::{anyhow, Result};
use glob::glob;
use tracing::{info, warn};

use crate::{
    event::NormalizedEvent,
    rule::{self, DirectiveRule, RuleType},
    utils::{self, ref_to_digit},
};

const DIRECTIVES_GLOB: &str = "directives_*.json";

#[derive(Deserialize, Debug, Clone)]
pub struct Directive {
    pub id: u64,
    pub name: String,
    pub priority: u8,
    #[serde(default)]
    pub disabled: bool,
    #[serde(default)]
    pub all_rules_always_active: bool,
    pub kingdom: String,
    pub category: String,
    pub rules: Vec<rule::DirectiveRule>,
    #[serde(rename(deserialize = "sticky_different"))]
    #[serde(default)]
    pub sticky_diffs: rule::StickyDiffData,
}

#[derive(Deserialize)]
pub struct Directives {
    pub directives: Vec<Directive>,
}

impl Directive {
    pub fn init_backlog_rules(&self, e: &NormalizedEvent) -> Vec<DirectiveRule> {
        let mut result = vec![];
        for (i, rule) in self.rules.iter().enumerate() {
            // all arc fields must be reset
            let mut r = rule.clone().reset_arc_fields();

            if i == 0 {
                r.start_time = Arc::new(Mutex::new(e.timestamp.timestamp()));

                // if flag is active, replace ANY and HOME_NET on the first rule with specific addresses from event
                if self.all_rules_always_active {
                    if r.from == "ANY" || r.from == "HOME_NET" || r.from == "!HOME_NET" {
                        r.from = e.src_ip.to_string();
                    }
                    if r.to == "ANY" || r.to == "HOME_NET" || r.to == "!HOME_NET" {
                        r.to = e.dst_ip.to_string();
                    }
                }
                // reference isn't allowed on first rule so we'll skip the rest
            } else {
                // for the rest, refer to the referenced stage if its not ANY or HOME_NET or !HOME_NET
                // if the reference is ANY || HOME_NET || !HOME_NET then refer to event if its in the format of
                // :refs
                if let Ok(v) = utils::ref_to_digit(&r.from) {
                    let vmin1 = usize::from(v - 1);
                    let refs = &self.rules[vmin1].from;
                    r.from = if refs != "ANY" && refs != "HOME_NET" && refs != "!HOME_NET" {
                        refs.to_string()
                    } else {
                        e.src_ip.to_string()
                    };
                }
                if let Ok(v) = utils::ref_to_digit(&r.to) {
                    let refs = &self.rules[usize::from(v - 1)].to;
                    r.to = if refs != "ANY" && refs != "HOME_NET" && refs != "!HOME_NET" {
                        refs.to_string()
                    } else {
                        e.dst_ip.to_string()
                    };
                }
                if let Ok(v) = utils::ref_to_digit(&r.port_from) {
                    let refs = &self.rules[usize::from(v - 1)].port_from;
                    r.port_from = if refs != "ANY" {
                        refs.to_string()
                    } else {
                        e.src_port.to_string()
                    };
                }
                if let Ok(v) = utils::ref_to_digit(&r.port_to) {
                    let refs = &self.rules[usize::from(v - 1)].port_to;
                    r.port_to = if refs != "ANY" {
                        refs.to_string()
                    } else {
                        e.dst_port.to_string()
                    };
                }

                // references in custom data
                if let Ok(v) = utils::ref_to_digit(&r.custom_data1) {
                    let refs = &self.rules[usize::from(v - 1)].custom_data1;
                    r.custom_data1 = if refs != "ANY" {
                        refs.to_string()
                    } else {
                        e.custom_data1.clone()
                    };
                }
                if let Ok(v) = utils::ref_to_digit(&r.custom_data2) {
                    let refs = &self.rules[usize::from(v - 1)].custom_data2;
                    r.custom_data2 = if refs != "ANY" {
                        refs.to_string()
                    } else {
                        e.custom_data2.clone()
                    };
                }
                if let Ok(v) = utils::ref_to_digit(&r.custom_data3) {
                    let refs = &self.rules[usize::from(v - 1)].custom_data3;
                    r.custom_data3 = if refs != "ANY" {
                        refs.to_string()
                    } else {
                        e.custom_data3.clone()
                    };
                }
            }
            result.push(r);
        }
        result.shrink_to_fit();
        result
    }
}

fn validate_rules(rules: &Vec<rule::DirectiveRule>) -> Result<()> {
    let mut stages: Vec<u8> = vec![];
    let highest_stage = rules.iter().fold(std::u8::MIN, |a, b| a.max(b.stage));
    for r in rules {
        if r.stage == 0 {
            return Err(anyhow!("rule stage cannot be zero"));
        }

        for s in &stages {
            if *s == r.stage {
                return Err(anyhow!("duplicate rule stage {} found", r.stage));
            }
        }
        if r.stage == 1 && r.occurrence != 1 {
            return Err(anyhow!("rule stage 1 must have occurrence = 1"));
        }
        if r.rule_type == RuleType::PluginRule {
            if r.plugin_id < 1 {
                return Err(anyhow!("rule stage {} plugin_id must be >= 1", r.stage));
            }
            for s in &r.plugin_sid {
                if *s < 1 {
                    return Err(anyhow!("rule stage {} plugin_sid must be >= 1", r.stage));
                }
            }
            if r.plugin_sid.is_empty() {
                return Err(anyhow!("plugin_sid cannot be empty"));
            }
        }
        if r.rule_type == RuleType::TaxonomyRule {
            if r.product.is_empty() {
                return Err(anyhow!(
                    "rule stage {} is a TaxonomyRule and requires product to be defined",
                    r.stage
                ));
            }
            if r.category.is_empty() {
                return Err(anyhow!(
                    "rule stage {} is a TaxonomyRule and requires category to be defined",
                    r.stage
                ));
            }
        }
        if r.reliability > 10 {
            return Err(anyhow!(
                "rule stage {} reliability must be between 0 to 10",
                r.stage
            ));
        }

        let is_first_rule = r.stage == 1;

        validate_port(r.port_from.clone(), is_first_rule, highest_stage)
            .map_err(|e| anyhow!("rule stage {} port_from is invalid: {}", r.stage, e))?;
        validate_port(r.port_to.clone(), is_first_rule, highest_stage)
            .map_err(|e| anyhow!("rule stage {} port_to is invalid: {}", r.stage, e))?;
        validate_fromto(r.from.clone(), is_first_rule, highest_stage)
            .map_err(|e| anyhow!("rule stage {} from address is invalid: {}", r.stage, e))?;
        validate_fromto(r.to.clone(), is_first_rule, highest_stage)
            .map_err(|e| anyhow!("rule stage {} to address is invalid: {}", r.stage, e))?;

        stages.push(r.stage);
    }

    Ok(())
}

fn validate_fromto(s: String, is_first_rule: bool, highest_stage: u8) -> Result<(), String> {
    if s == "ANY" || s == "HOME_NET" || s == "!HOME_NET" {
        return Ok(());
    }
    if s.is_empty() {
        return Err("empty string".to_string());
    }
    if is_reference(s.clone()) {
        if is_first_rule {
            return Err("first rule cannot have reference".to_string());
        }
        return validate_reference(s, highest_stage);
    }
    let slices: Vec<&str> = s.split(',').collect();
    for str in slices {
        let mut s = str.to_string();
        s = s.replace('!', "").trim().to_string();
        cidr::AnyIpCidr::from_str(&s).map_err(|e| format!("{s}: {e}"))?;
    }

    Ok(())
}

fn validate_port(s: String, is_first_rule: bool, highest_stage: u8) -> Result<(), String> {
    if s == "ANY" {
        return Ok(());
    }
    if is_reference(s.clone()) {
        if is_first_rule {
            return Err("first rule cannot have reference".to_string());
        }
        return validate_reference(s, highest_stage);
    }

    let slices: Vec<&str> = s.split(',').collect();
    for s in slices {
        let n = s
            .replace('!', "")
            .trim()
            .parse::<u16>()
            .map_err(|e| e.to_string())?;
        if !(1..=65535).contains(&n) {
            return Err(format!("{} is not a valid TCP/UDP port number", n));
        }
    }
    Ok(())
}

fn is_reference(str: String) -> bool {
    str.starts_with(':')
}

fn validate_reference(r: String, highest_stage: u8) -> Result<(), String> {
    let re = Regex::new(r"^:[1-9][0-9]?$").map_err(|e| e.to_string())?;
    if !re.is_match(&r) {
        return Err(r + " is not a valid reference");
    }

    if let Ok(n) = ref_to_digit(&r) {
        if n > highest_stage {
            return Err(r + " is not a valid reference");
        }
    }
    Ok(())
}

fn validate_directive(d: &Directive, loaded: &Vec<Directive>) -> Result<()> {
    for v in loaded {
        if d.id == v.id {
            return Err(anyhow!("directive ID {} already exist", d.id));
        }
    }
    if d.name.is_empty() {
        return Err(anyhow!("directive ID {} name is empty", d.id));
    }
    if d.kingdom.is_empty() {
        return Err(anyhow!("directive ID {} kingdom is empty", d.id));
    }
    if d.category.is_empty() {
        return Err(anyhow!("directive ID {} category is empty", d.id));
    }
    if d.priority < 1 || d.priority > 5 {
        return Err(anyhow!(
            "directive ID {} priority must be between 1 to 5",
            d.id
        ));
    }
    if d.rules.len() <= 1 {
        return Err(anyhow!(
            "directive ID {} has no rule or only has one and therefore will never expire",
            d.id
        ));
    }
    validate_rules(&d.rules)
        .map_err(|e| anyhow!("Directive ID {} rules has error: {}", d.id, e))?;
    Ok(())
}

pub fn load_directives(test_env: bool, sub_path: Option<Vec<String>>) -> Result<Vec<Directive>> {
    let cfg_dir = utils::config_dir(test_env, sub_path)?;
    let glob_pattern = cfg_dir.to_string_lossy().to_string() + "/" + DIRECTIVES_GLOB;
    let mut dirs = Directives { directives: vec![] };
    for file_path in glob(&glob_pattern)?.flatten() {
        info!("reading {:?}", file_path);
        let s = fs::read_to_string(file_path.clone())?;
        let loaded: Directives =
            serde_json::from_str(&s).map_err(|e| anyhow!("{:?}: {}", file_path, e.to_string()))?;
        for d in loaded.directives {
            if d.disabled {
                warn!(directive.id = d.id, "skipping disabled directive");
                continue;
            }
            validate_directive(&d, &dirs.directives)
                .map_err(|e| anyhow!("{:?}: {}", file_path, e.to_string()))?;
            dirs.directives.push(d);
        }
    }
    if dirs.directives.is_empty() {
        return Err(anyhow!("cannot load any directive"));
    }
    info!("{} directives found and loaded", dirs.directives.len());
    dirs.directives.shrink_to_fit();
    Ok(dirs.directives)
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_load_directives() {
        let res = load_directives(
            true,
            Some(vec!["directives".to_owned(), "directive1".to_owned()]),
        );
        assert!(res.is_err());
        assert!(res
            .unwrap_err()
            .to_string()
            .contains("directive ID 1 already exist"));

        let dir2_path = vec!["directives".to_owned(), "directive2".to_owned()];

        for n in 1..29 {
            let mut dir = dir2_path.clone();
            dir.push(n.to_string());
            let res = load_directives(true, Some(dir.clone()));
            println!("directory is: {:?}", dir.clone());

            if res.is_ok() {
                panic!("all test should results in err");
            } else if let Err(e) = res {
                let s = e.to_string();
                match n {
                    1 => assert!(s.contains("missing field `rules`")),
                    2 => assert!(s.contains("kingdom is empty")),
                    3 => assert!(s.contains("priority must be between 1 to 5")),
                    4 => assert!(s.contains("invalid value: integer `-1`")),
                    5 => assert!(s.contains("invalid rule type")),
                    6 => assert!(s.contains("rule stage 1 plugin_id must be >= 1")),
                    7 => assert!(s.contains("plugin_sid cannot be empty")),
                    8 => assert!(s.contains("plugin_sid must be >= 1")),
                    9 => assert!(s.contains("requires product to be defined")),
                    10 => assert!(s.contains("requires category to be defined")),
                    11 => assert!(s.contains("invalid IP address syntax")),
                    12 => assert!(s.contains("missing field `to`")),
                    13 => assert!(s.contains("port_from is invalid")),
                    14 => assert!(s.contains("port_to is invalid")),
                    15 => assert!(s.contains("rule stage cannot be zero")),
                    16 => assert!(s.contains("duplicate rule stage")),
                    17 => assert!(s.contains("rule stage 1 must have occurrence = 1")),
                    18 => assert!(s.contains("name is empty")),
                    19 => assert!(s.contains("category is empty")),
                    20 => assert!(s.contains("will never expire")),
                    21 => assert!(s.contains("reliability must be between 0 to 10")),
                    22 => assert!(s.contains("empty string")),
                    23 => assert!(s.contains("first rule cannot have reference")),
                    24 => assert!(s.contains("first rule cannot have reference")),
                    25 => assert!(s.contains("is not a valid reference")),
                    26 => assert!(s.contains("is not a valid reference")),
                    _ => assert!(s.contains("cannot load any directive")), // for 27 and 28
                }
            }
        }
    }

    #[test]
    fn test_init_backlog_rules() {
        let dir_path = vec!["directives".to_owned(), "directive3".to_owned()];
        let o = load_directives(true, Some(dir_path)).unwrap();
        let d = o.first().unwrap();
        let e = NormalizedEvent {
            src_ip: "192.168.0.1".parse().unwrap(),
            dst_ip: "8.8.8.1".parse().unwrap(),

            ..Default::default()
        };
        let r = d.init_backlog_rules(&e);
        assert_eq!(r.len(), 3);
    }
}
