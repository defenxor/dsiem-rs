use std::ops::Range;

use dsiem::rule::{SIDPair, TaxoPair};
use rand::{distributions::Alphanumeric, Rng};

pub fn gen_sidpairs(
    correct_pair: SIDPair,
    n: u64,
    plugin_id: Range<u64>,
    plugin_sid: Range<u64>,
) -> Vec<SIDPair> {
    let mut pairs = vec![];
    for i in 0..n {
        let plugin_id = if i < n / 2 {
            rand::thread_rng().gen_range(plugin_id.clone())
        } else {
            // use the same plugin_id for the 2nd half
            correct_pair.plugin_id
        };
        let plugin_sid = (plugin_sid.clone()).collect::<Vec<u64>>();
        pairs.push(SIDPair {
            plugin_id,
            plugin_sid,
        });
    }
    pairs.push(correct_pair);
    pairs
}

pub fn gen_taxopairs(correct_pair: TaxoPair, n: u64) -> Vec<TaxoPair> {
    let mut pairs = vec![];
    for i in 0..n {
        let product: Vec<String> = if i < n / 2 {
            vec![rand::thread_rng()
                .sample_iter(&Alphanumeric)
                .take(10)
                .map(char::from)
                .collect()]
        } else {
            // use one of the correct product for the 2nd half
            let pos = rand::thread_rng().gen_range(0..correct_pair.product.len());
            vec![correct_pair.product[pos].clone()]
        };
        let category: String = rand::thread_rng()
            .sample_iter(&Alphanumeric)
            .take(10)
            .map(char::from)
            .collect();
        pairs.push(TaxoPair { product, category });
    }
    pairs.push(correct_pair);
    pairs
}
