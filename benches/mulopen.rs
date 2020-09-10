#![feature(test)]

extern crate test;

use mpc::mulopen;
use mpc::testutil;
use secp256k1::group::Gej;
use secp256k1::scalar;
use test::Bencher;

#[bench]
fn bench_initial_message_batch(b: &mut Bencher) {
    let n = 100;
    let k = 33;
    let batch_size = 5;

    let h = Gej::new_random_using_thread_rng();
    let indices = scalar::random_scalars_using_thread_rng(n);

    let (mut a_shares_by_player, _, _, _) =
        testutil::random_sharing_batch(n, k, batch_size, &indices, &h);
    let (mut b_shares_by_player, _, _, _) =
        testutil::random_sharing_batch(n, k, batch_size, &indices, &h);
    let (mut z_shares_by_player, _) = testutil::zero_sharing_batch(n, k, batch_size, &indices, &h);
    let a_vshares = a_shares_by_player.pop().unwrap();
    let b_vshares = b_shares_by_player.pop().unwrap();
    let z_vshares = z_shares_by_player.pop().unwrap();

    b.iter(|| {
        let _ = mulopen::initial_message_batch(
            a_vshares.clone(),
            b_vshares.clone(),
            z_vshares.clone(),
            &h,
        );
    });
}

#[bench]
fn bench_handle_message_batch(b: &mut Bencher) {
    let n = 100;
    let k = 33;
    let batch_size = 1;

    let threshold = 2 * k - 1;
    let h = Gej::new_random_using_thread_rng();
    let indices = scalar::random_scalars_using_thread_rng(n);

    let (mut a_shares_by_player, a_commitments, _, _) =
        testutil::random_sharing_batch(n, k, batch_size, &indices, &h);
    let (mut b_shares_by_player, b_commitments, _, _) =
        testutil::random_sharing_batch(n, k, batch_size, &indices, &h);
    let (mut z_shares_by_player, z_commitments) =
        testutil::zero_sharing_batch(n, k, batch_size, &indices, &h);
    let mut state = Vec::with_capacity(n);
    for _batch in 0..batch_size {
        state.push(Vec::with_capacity(threshold));
    }

    let message_batch = mulopen::initial_message_batch(
        a_shares_by_player.pop().unwrap(),
        b_shares_by_player.pop().unwrap(),
        z_shares_by_player.pop().unwrap(),
        &h,
    );

    b.iter(|| {
        let _ = mulopen::handle_message_batch(
            &mut state.clone(),
            message_batch.clone(),
            &a_commitments,
            &b_commitments,
            &z_commitments,
            &h,
        );
    });
}
