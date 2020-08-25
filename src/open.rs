use secp256k1::scalar::Scalar;
use shamir::vss::{self, SharingCommitment, VShare};

use crate::params::Parameters;

pub type OpenResult = Result<Option<Vec<(Scalar, Scalar)>>, OpenError>;

#[derive(Debug, PartialEq)]
pub enum OpenError {
    InvalidIndex,
    DuplicateIndex,
    InvalidShare,
    InconsistentIndices,
    InvalidBatchSize,
}

pub struct InstanceParams<'a> {
    commitment_batch: &'a [SharingCommitment],
}

impl<'a> InstanceParams<'a> {
    pub fn new(commitment_batch: &'a [SharingCommitment]) -> Self {
        assert!(commitment_batch
            .windows(2)
            .all(|sl| sl[0].len() == sl[1].len()));
        Self { commitment_batch }
    }

    pub fn threshold(&self) -> usize {
        self.commitment_batch[0].len()
    }
}

pub struct State {
    vshare_bufs: Vec<Vec<VShare>>,
}

impl State {
    pub fn new(inst_params: &InstanceParams) -> Self {
        let b = inst_params.commitment_batch.len();
        let mut vshare_bufs = Vec::with_capacity(b);
        for _ in 0..b {
            vshare_bufs.push(Vec::with_capacity(inst_params.threshold()));
        }
        State { vshare_bufs }
    }

    pub fn contains_vshare_with_index(&self, index: &Scalar) -> bool {
        self.vshare_bufs[0]
            .iter()
            .any(|&vs| index == &vs.share.index)
    }

    pub fn shares_received(&self) -> usize {
        self.vshare_bufs[0].len()
    }

    fn accept_vshare_batch(&mut self, vshare_batch: Vec<VShare>) {
        for (buf, vshare) in self.vshare_bufs.iter_mut().zip(vshare_batch.into_iter()) {
            buf.push(vshare);
        }
        debug_assert!(self
            .vshare_bufs
            .windows(2)
            .all(|sl| sl[0].len() == sl[1].len()));
    }

    pub fn reconstruct_values(&self) -> Vec<(Scalar, Scalar)> {
        self.vshare_bufs
            .iter()
            .map(|buf| vss::interpolate_shares_at_zero(buf.iter()))
            .collect()
    }
}

pub fn handle_vshare_batch(
    mut state: State,
    inst_params: &InstanceParams,
    params: &Parameters,
    vshare_batch: Vec<VShare>,
) -> (State, OpenResult) {
    use OpenError::*;

    debug_assert_eq!(state.vshare_bufs.len(), inst_params.commitment_batch.len());
    let b = state.vshare_bufs.len();

    if vshare_batch.len() != b {
        return (state, Err(InvalidBatchSize));
    }
    if !all_indices_equal_in_vshare_batch(&vshare_batch) {
        return (state, Err(InconsistentIndices));
    }

    let index = &vshare_batch[0].share.index;
    if !params.indices.contains(index) {
        return (state, Err(InvalidIndex));
    }
    if state.contains_vshare_with_index(index) {
        return (state, Err(DuplicateIndex));
    }
    for (vshare, commitment) in vshare_batch.iter().zip(inst_params.commitment_batch.iter()) {
        if !vss::vshare_is_valid(vshare, commitment, &params.h) {
            return (state, Err(InvalidShare));
        }
    }

    if state.shares_received() == inst_params.threshold() {
        return (state, Ok(None));
    }
    state.accept_vshare_batch(vshare_batch);
    if state.shares_received() == inst_params.threshold() {
        let res = state.reconstruct_values();
        (state, Ok(Some(res)))
    } else {
        (state, Ok(None))
    }
}

fn all_indices_equal_in_vshare_batch(vshares: &[VShare]) -> bool {
    vshares
        .windows(2)
        .all(|w| w[0].share.index == w[1].share.index)
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::group::Gej;
    use secp256k1::scalar;
    use shamir::vss;

    fn transpose<T: Clone>(mat: Vec<Vec<T>>) -> Vec<Vec<T>> {
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

    fn random_sharing_batch(
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
            commitment_batch.push(Vec::with_capacity(k));
            commitment_batch[i].resize_with(k, Gej::default);
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

    #[test]
    fn handling_correct_shares() {
        let n = 10;
        let k = 5;
        let b = 3;

        let indices = scalar::random_scalars_using_thread_rng(n);
        let h = Gej::new_random_using_thread_rng();
        let (vshare_batches, commitment_batch, secrets, decommitments) =
            random_sharing_batch(n, k, b, &indices, &h);

        let inst_params = InstanceParams::new(&commitment_batch);
        let params = Parameters { indices, h };
        let state = State::new(&inst_params);

        vshare_batches
            .into_iter()
            .enumerate()
            .fold(state, |state, (i, vshare_batch)| {
                let (state, res) = handle_vshare_batch(state, &inst_params, &params, vshare_batch);
                if i + 1 != k {
                    assert_eq!(res, Ok(None));
                } else {
                    let reconstructed_values = res.unwrap().unwrap();
                    assert!(secrets
                        .iter()
                        .zip(decommitments.iter())
                        .eq(reconstructed_values.iter().map(|(s, d)| (s, d))));
                }
                state
            });
    }
}
