use metered::{metered, Throughput};

#[derive(Default)]
pub struct Eps {
    pub metrics: EpsRegistry,
}

#[metered(registry = EpsRegistry, visibility = pub)]
impl Eps {
    #[measure([Throughput])]
    pub fn count(&self) {}
}
