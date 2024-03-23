use super::{IntelChecker, IntelResult};

mod wise;

pub struct Checker {
    pub plugin: Box<dyn IntelChecker>,
    pub name: String,
    pub enabled: bool,
}

impl Checker {
    fn new(plugin: Box<dyn IntelChecker>, name: &str) -> Checker {
        Checker { plugin, name: name.to_string(), enabled: false }
    }
}

pub fn load_plugins() -> Vec<Checker> {
    let wise = Checker::new(Box::<wise::Wise>::default(), "Wise");

    vec![wise]
}
