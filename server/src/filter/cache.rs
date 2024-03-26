use arcstr::ArcStr;
use quick_cache::unsync::Cache;

use super::FilterTarget;

pub fn create_sid_cache(c: &[FilterTarget]) -> Cache<(u64, u64), ()> {
    // prepare a thread local cache for quick check
    let pairs: Vec<(u64, u64)> = c
        .iter()
        .flat_map(|t| t.sid_pairs.iter().flat_map(|p| p.plugin_sid.iter().map(|s| (p.plugin_id, *s))))
        .collect();
    let mut sid_cache: Cache<(u64, u64), ()> = Cache::new(pairs.len());
    pairs.iter().for_each(|p| {
        sid_cache.insert(*p, ());
    });
    sid_cache
}

pub fn create_taxo_cache(c: &[FilterTarget]) -> Cache<(ArcStr, ArcStr), ()> {
    // prepare a thread local cache for quick check
    let pairs: Vec<(ArcStr, ArcStr)> = c
        .iter()
        .flat_map(|t| {
            t.taxo_pairs.iter().flat_map(|pair| pair.product.iter().map(|p| (p.clone(), pair.category.clone())))
        })
        .collect();
    let mut taxo_cache: Cache<(ArcStr, ArcStr), ()> = Cache::new(pairs.len());
    pairs.iter().for_each(|p| {
        taxo_cache.insert(p.clone(), ());
    });
    taxo_cache
}
