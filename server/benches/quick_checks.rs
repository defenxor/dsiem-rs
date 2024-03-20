// use this to evaluate potential optimizations

use dsiem::{
    event::NormalizedEvent,
    rule::{quick_check_plugin_rule, quick_check_taxo_rule, SIDPair, TaxoPair},
};
use rayon::prelude::*;

use criterion::{black_box, criterion_group, criterion_main, Criterion};

use quick_cache::unsync::Cache;

mod generator;

#[inline(always)]
pub fn quick_check_plugin_rule_with_cache(
    cache: &mut Cache<(u64, u64), ()>,
    pairs: &[SIDPair],
    e: &NormalizedEvent,
) -> bool {
    if cache.get(&(e.plugin_id, e.plugin_sid)).is_some() {
        return true;
    };
    let found = pairs
        .iter()
        .filter(|v| v.plugin_id == e.plugin_id)
        .any(|v| v.plugin_sid.iter().any(|s| *s == e.plugin_sid));
    if found {
        cache.insert((e.plugin_id, e.plugin_sid), ());
    };
    found
}

#[inline(always)]
pub fn quick_check_plugin_rule_with_rayon(pairs: &[SIDPair], e: &NormalizedEvent) -> bool {
    pairs
        .par_iter()
        .filter(|v| v.plugin_id == e.plugin_id)
        .any(|v| v.plugin_sid.iter().any(|x| *x == e.plugin_sid))
}

fn bench_quick_check_plugin_rule(c: &mut Criterion) {
    let correct_pair = SIDPair {
        plugin_id: 1,
        plugin_sid: vec![1, 2, 3, 4, 5, 6, 7, 8, 9, 10],
    };
    let event = NormalizedEvent {
        plugin_id: 1,
        plugin_sid: 9,
        ..Default::default()
    };

    let mut cache: Cache<(u64, u64), ()> = Cache::new(1024);

    let sid_pairs = generator::gen_sidpairs(correct_pair, 2000, 2..1000, 1..100);

    sid_pairs.iter().for_each(|pair| {
        pair.plugin_sid.iter().for_each(|sid| {
            cache.insert((pair.plugin_id, *sid), ());
        });
    });

    c.bench_function("qc_plugin_rule_base", |b| {
        b.iter(|| quick_check_plugin_rule(black_box(&sid_pairs), black_box(&event)))
    });
    c.bench_function("qc_plugin_rule_with_cache", |b| {
        b.iter(|| {
            quick_check_plugin_rule_with_cache(
                black_box(&mut cache),
                black_box(&sid_pairs),
                black_box(&event),
            )
        })
    });
    c.bench_function("qc_plugin_rule_with_rayon", |b| {
        b.iter(|| quick_check_plugin_rule_with_rayon(black_box(&sid_pairs), black_box(&event)))
    });
}

#[inline(always)]
pub fn quick_check_taxo_rule_with_rayon(pairs: &[TaxoPair], e: &NormalizedEvent) -> bool {
    pairs
        .par_iter()
        .filter(|v| v.product.iter().any(|x| *x == e.product))
        .any(|v| v.category == e.category)
}

fn bench_quick_check_taxo_rule(c: &mut Criterion) {
    let correct_pair = TaxoPair {
        product: vec!["Suricata".to_string(), "Snort".to_string()],
        category: "Firewall".to_string(),
    };
    let event = NormalizedEvent {
        product: correct_pair.product[1].clone(),
        category: correct_pair.category.clone(),
        ..Default::default()
    };
    let taxo_pairs = generator::gen_taxopairs(correct_pair, 2000);

    c.bench_function("qc_taxo_rule_base", |b| {
        b.iter(|| quick_check_taxo_rule(black_box(&taxo_pairs), black_box(&event)))
    });
    c.bench_function("qc_taxo_rule_with_rayon", |b| {
        b.iter(|| quick_check_taxo_rule_with_rayon(black_box(&taxo_pairs), black_box(&event)))
    });
}

criterion_group! {
    name = benches;
    config = Criterion::default();
    targets = bench_quick_check_plugin_rule, bench_quick_check_taxo_rule
}
criterion_main!(benches);
