use secp256k1::group::Gej;
use secp256k1::scalar::Scalar;
use shamir::vss::{self, SharingCommitment, VShare};
use std::collections::HashMap;
use std::ops::IndexMut;

pub fn transpose<T: Clone>(mat: Vec<Vec<T>>) -> Vec<Vec<T>> {
    debug_assert!(mat.windows(2).all(|sl| sl[0].len() == sl[1].len()));
    let num_rows = mat.len();
    let num_cols = mat[0].len();
    let mut transposed = Vec::with_capacity(num_cols);
    for i in 0..num_cols {
        transposed.push(Vec::with_capacity(num_rows));
        for j in 0..num_rows {
            transposed[i].push(mat[j][i].clone());
        }
    }
    transposed
}

pub fn random_sharing_batch(
    n: usize,
    k: usize,
    b: usize,
    indices: &[Scalar],
    h: &Gej,
) -> (
    Vec<Vec<VShare>>,
    Vec<SharingCommitment>,
    Vec<Scalar>,
    Vec<Scalar>,
) {
    let mut secrets = Vec::with_capacity(b);
    let mut decommitments = Vec::with_capacity(b);
    for _ in 0..b {
        secrets.push(Scalar::new_random_using_thread_rng());
        decommitments.push(Scalar::new_random_using_thread_rng());
    }

    let mut sharing_batch: Vec<Vec<VShare>> = Vec::with_capacity(b);
    let mut commitment_batch: Vec<shamir::vss::SharingCommitment> = Vec::with_capacity(b);
    for i in 0..b {
        sharing_batch.push(Vec::with_capacity(n));
        sharing_batch[i].resize_with(n, VShare::default);
        let mut v = Vec::with_capacity(k);
        v.resize_with(k, Gej::default);
        commitment_batch.push(SharingCommitment::new_from_vec(v));
        vss::vshare_secret_and_decommitment_in_place(
            &mut sharing_batch[i],
            &mut commitment_batch[i],
            &h,
            &indices,
            &secrets[i],
            &decommitments[i],
        );
    }
    let vshare_batches = transpose(sharing_batch);

    (vshare_batches, commitment_batch, secrets, decommitments)
}

pub fn zero_sharing_batch(
    n: usize,
    k: usize,
    b: usize,
    indices: &[Scalar],
    h: &Gej,
) -> (Vec<Vec<VShare>>, Vec<SharingCommitment>) {
    let mut sharing_batch: Vec<Vec<VShare>> = Vec::with_capacity(b);
    let mut commitment_batch: Vec<shamir::vss::SharingCommitment> = Vec::with_capacity(b);
    for i in 0..b {
        sharing_batch.push(Vec::with_capacity(n));
        sharing_batch[i].resize_with(n, VShare::default);
        let mut v = Vec::with_capacity(k);
        v.resize_with(k, Gej::default);
        commitment_batch.push(SharingCommitment::new_from_vec(v));
        vss::vshare_secret_in_place(
            &mut sharing_batch[i],
            &mut commitment_batch[i],
            &h,
            &indices,
            &Scalar::zero(),
        );
    }
    let vshare_batches = transpose(sharing_batch);

    (vshare_batches, commitment_batch)
}

pub fn rxg_inputs(
    k: usize,
    b: usize,
    indices: &[Scalar],
    h: &Gej,
) -> (
    HashMap<Scalar, Vec<Vec<VShare>>>,
    Vec<Vec<SharingCommitment>>,
) {
    let n = indices.len();
    let mut inputs_by_player = HashMap::<_, Vec<Vec<_>>>::with_capacity(n);
    for index in indices.iter() {
        let mut v = Vec::with_capacity(b);
        v.resize_with(b, || Vec::with_capacity(k));
        inputs_by_player.insert(*index, v);
    }
    let mut commitments = Vec::with_capacity(b);
    for _batch in 0..b {
        commitments.push(Vec::with_capacity(k));
    }

    let mut vshares = Vec::with_capacity(n);
    vshares.resize_with(n, VShare::default);
    let mut commitment = SharingCommitment::default_with_len(k);
    for batch in 0..b {
        for _coeff in 0..k {
            vss::vshare_secret_in_place(
                &mut vshares,
                &mut commitment,
                h,
                indices,
                &Scalar::new_random_using_thread_rng(),
            );
            for vshare in vshares.iter() {
                inputs_by_player
                    .get_mut(&vshare.share.index)
                    .expect("inputs for player should exist")
                    .index_mut(batch)
                    .push(*vshare);
            }
            commitments[batch].push(commitment.clone());
        }
    }

    (inputs_by_player, commitments)
}
