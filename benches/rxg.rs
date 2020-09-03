#![feature(test)]

extern crate test;

use mpc::rng;
use mpc::testutil;
use secp256k1::group::Gej;
use secp256k1::scalar;
use test::Bencher;

#[bench]
fn bench_initial_messages_rng(b: &mut Bencher) {
    let n = 100;
    let k = 33;
    let batch_size = 3;

    let h = Gej::new_random_using_thread_rng();
    let indices = scalar::random_scalars_using_thread_rng(n);
    let (mut inputs_by_player, _) = testutil::rxg_inputs(k, batch_size, &indices, &h);
    let inputs = inputs_by_player.remove(&indices[0]).unwrap();

    b.iter(|| rng::initial_messages_batch_rng(&inputs, &indices));
}

#[bench]
fn bench_initial_messages_rzg(b: &mut Bencher) {
    let n = 100;
    let k = 33;
    let batch_size = 3;

    let h = Gej::new_random_using_thread_rng();
    let indices = scalar::random_scalars_using_thread_rng(n);
    let (mut inputs_by_player, _) = testutil::rxg_inputs(k - 1, batch_size, &indices, &h);
    let inputs = inputs_by_player.remove(&indices[0]).unwrap();

    b.iter(|| rng::initial_messages_batch_rzg(&inputs, &indices));
}

#[bench]
fn bench_own_commitments_rng(b: &mut Bencher) {
    let n = 10;
    let k = 5;
    let batch_size = 3;

    let h = Gej::new_random_using_thread_rng();
    let indices = scalar::random_scalars_using_thread_rng(n);
    let index = indices[0];
    let (_, commitments) = testutil::rxg_inputs(k, batch_size, &indices, &h);

    b.iter(|| rng::own_commitment_batch_rng(&commitments, &index));
}

#[bench]
fn bench_own_commitments_rzg(b: &mut Bencher) {
    let n = 10;
    let k = 5;
    let batch_size = 3;

    let h = Gej::new_random_using_thread_rng();
    let indices = scalar::random_scalars_using_thread_rng(n);
    let index = indices[0];
    let (_, commitments) = testutil::rxg_inputs(k - 1, batch_size, &indices, &h);

    b.iter(|| rng::own_commitment_batch_rzg(&commitments, &index));
}
