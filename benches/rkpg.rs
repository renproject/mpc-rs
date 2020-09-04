#![feature(test)]

extern crate test;

use mpc::rkpg::{self, State};
use mpc::testutil;
use secp256k1::group::Gej;
use secp256k1::scalar::{self, Scalar};
use shamir::rs::Precompute;
use shamir::sss::Share;
use shamir::vss::SharingCommitment;
use test::Bencher;

fn setup(
    indices: &[Scalar],
    k: usize,
    b: usize,
) -> (
    State,
    Vec<Vec<Share>>,
    Precompute,
    Vec<SharingCommitment>,
    Gej,
) {
    let n = indices.len();
    let h = Gej::new_random_using_thread_rng();
    let precompute = Precompute::new(indices.iter());

    let (all_vshare_batches, commitment_batch, secrets, _) =
        testutil::random_sharing_batch(n, k, b, &indices, &h);

    let mut expected_pubkeys = Vec::with_capacity(b);
    for secret in secrets {
        let mut pubkey = Gej::default();
        pubkey.scalar_base_mul(&secret);
        expected_pubkeys.push(pubkey);
    }

    let mut all_initial_message_batches = Vec::with_capacity(n);
    for vshare_batch in all_vshare_batches {
        all_initial_message_batches.push(rkpg::initial_messages_batch(&vshare_batch));
    }
    let state = State::new(&indices, b);

    (
        state,
        all_initial_message_batches,
        precompute,
        commitment_batch,
        h,
    )
}

#[bench]
fn bench_handle_share_no_reconstruct(b: &mut Bencher) {
    let n = 100;
    let k = 33;
    let batch_size = 5;
    let indices = scalar::random_scalars_using_thread_rng(n);

    let (state, all_initial_message_batches, precompute, commitment_batch, h) =
        setup(&indices, k, batch_size);

    let share_batch = all_initial_message_batches[0].clone();
    b.iter(|| {
        let res = rkpg::handle_share_batch(
            &mut state.clone(),
            share_batch.clone(),
            &precompute,
            &commitment_batch,
            &h,
        );
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), None);
    })
}

#[bench]
fn bench_handle_share_reconstruct(b: &mut Bencher) {
    let n = 100;
    let k = 33;
    let batch_size = 5;
    let indices = scalar::random_scalars_using_thread_rng(n);

    let (mut state, mut all_initial_message_batches, precompute, commitment_batch, h) =
        setup(&indices, k, batch_size);

    let last_message_batches = all_initial_message_batches.split_off(n - k);
    for share_batch in all_initial_message_batches {
        let res =
            rkpg::handle_share_batch(&mut state, share_batch, &precompute, &commitment_batch, &h);
        assert!(res.is_ok());
        assert_eq!(res.unwrap(), None);
    }

    let share_batch = last_message_batches[0].clone();
    b.iter(|| {
        let res = rkpg::handle_share_batch(
            &mut state.clone(),
            share_batch.clone(),
            &precompute,
            &commitment_batch,
            &h,
        );
        assert!(res.as_ref().map(Option::is_some).unwrap_or(false));
    })
}
