use super::VulnChecker;
use super::VulnResult;

mod nesd;
pub struct Checker {
    pub plugin: Box<dyn VulnChecker>,
    pub name: String,
    pub enabled: bool,
}

impl Checker {
    fn new(plugin: Box<dyn VulnChecker>, name: &str) -> Checker {
        Checker {
            plugin,
            name: name.to_string(),
            enabled: false,
        }
    }
}

pub fn load_plugins() -> Vec<Checker> {
    let nesd = Checker::new(Box::<nesd::Nesd>::default(), "Nesd");

    vec![nesd]
}
