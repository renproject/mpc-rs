#![feature(test)]

extern crate test;

use mpc::brng;
use mpc::params::Parameters;
use secp256k1::group::Gej;
use secp256k1::scalar::{self, Scalar};
use shamir::sss::Share;
use shamir::vss::{self, VShare};
use test::Bencher;

#[bench]
fn bench_output_shares_and_commitments(b: &mut Bencher) {
    let k = 33;
    let batch_size = 10;

    let index = Scalar::new_random_using_thread_rng();

    let mut vshare_batches = Vec::with_capacity(batch_size);
    let mut commitment_batches = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        vshare_batches.push(Vec::with_capacity(k));
        commitment_batches.push(Vec::with_capacity(k));
    }
    for (vshare_batch, commitment_batch) in
        vshare_batches.iter_mut().zip(commitment_batches.iter_mut())
    {
        for _ in 0..k {
            let value = Scalar::new_random_using_thread_rng();
            let decommitment = Scalar::new_random_using_thread_rng();
            let vshare = VShare {
                share: Share { index, value },
                decommitment,
            };
            vshare_batch.push(vshare);

            let commitment = shamir::testutil::random_commitment_using_thread_rng(k);
            commitment_batch.push(commitment);
        }
    }

    let iter = vshare_batches
        .iter()
        .zip(commitment_batches.iter())
        .map(|(s, c)| s.iter().zip(c.iter()));

    b.iter(|| {
        let (_, _) = brng::output_sharing_batch(iter.clone());
    });
}

#[bench]
fn bench_verify_shares_and_commitments(b: &mut Bencher) {
    // NOTE: Smaller values for the parameters are used here so that the benchmark completes in a
    // reasonable amount of time.
    let n = 10;
    let k = 3;
    let batch_size = 2;

    let indices = scalar::random_scalars_using_thread_rng(n);
    let index = indices[0];
    let h = Gej::new_random_using_thread_rng();

    let mut vshare_batches = Vec::with_capacity(batch_size);
    let mut commitment_batches = Vec::with_capacity(batch_size);
    for _ in 0..batch_size {
        vshare_batches.push(Vec::with_capacity(k));
        commitment_batches.push(Vec::with_capacity(k));
    }
    for (vshare_batch, commitment_batch) in
        vshare_batches.iter_mut().zip(commitment_batches.iter_mut())
    {
        for _ in 0..k {
            let (shares, commitment) =
                vss::vshare_secret(&h, &indices, &Scalar::new_random_using_thread_rng(), k);
            vshare_batch.push(shares[0]);
            commitment_batch.push(commitment);
        }
    }
    let params = Parameters { indices, index, h };

    let iter = vshare_batches
        .iter()
        .zip(commitment_batches.iter())
        .map(|(s, c)| s.iter().zip(c.iter()));

    b.iter(|| {
        assert!(brng::is_valid(k, &params, iter.clone()).is_ok());
    });
}
