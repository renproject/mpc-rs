#![feature(test)]

extern crate test;

use mpc::open::{InstanceParams, State};
use mpc::params::Parameters;
use mpc::testutil;
use secp256k1::group::Gej;
use secp256k1::scalar;
use test::Bencher;

#[bench]
fn bench_handle_share_batch(b: &mut Bencher) {
    let n = 100;
    let k = 33;
    let batch_size = 10;

    let indices = scalar::random_scalars_using_thread_rng(n);
    let index = indices[0];
    let h = Gej::new_random_using_thread_rng();
    let (vshare_batches, commitment_batch, _, _) =
        testutil::random_sharing_batch(n, k, batch_size, &indices, &h);

    let inst_params = InstanceParams::new(commitment_batch);
    let params = Parameters { indices, index, h };
    let state = State::new(&inst_params);

    b.iter(|| {
        let _ = state
            .clone()
            .handle_vshare_batch(&inst_params, &params, vshare_batches[0].clone());
    });
}
