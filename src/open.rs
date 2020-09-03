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

pub struct InstanceParams {
    commitment_batch: Vec<SharingCommitment>,
}

impl InstanceParams {
    pub fn new(commitment_batch: Vec<SharingCommitment>) -> Self {
        assert!(commitment_batch
            .windows(2)
            .all(|sl| sl[0].len() == sl[1].len()));
        Self { commitment_batch }
    }

    pub fn threshold(&self) -> usize {
        self.commitment_batch[0].len()
    }
}

#[derive(Clone)]
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

    pub fn handle_vshare_batch(
        &mut self,
        inst_params: &InstanceParams,
        params: &Parameters,
        vshare_batch: Vec<VShare>,
    ) -> OpenResult {
        use OpenError::*;

        debug_assert_eq!(self.vshare_bufs.len(), inst_params.commitment_batch.len());
        let b = self.vshare_bufs.len();

        if vshare_batch.len() != b {
            return Err(InvalidBatchSize);
        }
        if !all_indices_equal_in_vshare_batch(&vshare_batch) {
            return Err(InconsistentIndices);
        }

        let index = &vshare_batch[0].share.index;
        if !params.indices.contains(index) {
            return Err(InvalidIndex);
        }
        if self.contains_vshare_with_index(index) {
            return Err(DuplicateIndex);
        }
        for (vshare, commitment) in vshare_batch.iter().zip(inst_params.commitment_batch.iter()) {
            if !vss::vshare_is_valid(vshare, commitment, &params.h) {
                return Err(InvalidShare);
            }
        }

        // Add the share batch to the buffer only if we don't have enough for reconstruction, and only
        // return the reconstructed values upon adding the last share batch.
        if self.shares_received() == inst_params.threshold() {
            return Ok(None);
        }
        self.accept_vshare_batch(vshare_batch);

        if self.shares_received() == inst_params.threshold() {
            let res = self.reconstruct_values();
            Ok(Some(res))
        } else {
            Ok(None)
        }
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
    use crate::testutil;
    use secp256k1::group::Gej;
    use secp256k1::scalar;

    #[test]
    fn handling_correct_shares() {
        let n = 10;
        let k = 5;
        let b = 3;

        let indices = scalar::random_scalars_using_thread_rng(n);
        let index = indices[0];
        let h = Gej::new_random_using_thread_rng();
        let (vshare_batches, commitment_batch, secrets, decommitments) =
            testutil::random_sharing_batch(n, k, b, &indices, &h);

        let inst_params = InstanceParams::new(commitment_batch);
        let params = Parameters { indices, index, h };
        let state = State::new(&inst_params);

        vshare_batches
            .into_iter()
            .enumerate()
            .fold(state, |mut state, (i, vshare_batch)| {
                let res = state.handle_vshare_batch(&inst_params, &params, vshare_batch);
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
