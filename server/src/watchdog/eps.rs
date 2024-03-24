use metered::{metered, HitCount, Throughput};

#[derive(Default)]
pub struct Eps {
    pub metrics: EpsRegistry,
}

#[metered(registry = EpsRegistry, visibility = pub)]
impl Eps {
    #[measure([Throughput, HitCount])]
    pub fn count(&self) {}
}
