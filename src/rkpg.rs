use secp256k1::group::Gej;
use secp256k1::scalar::Scalar;
use shamir::rs::{self, Precompute};
use shamir::sss::Share;
use shamir::vss::{SharingCommitment, VShare};

#[derive(Debug, Eq, PartialEq)]
pub enum RKPGError {
    IndexOutOfRange,
    EmptyBatch,
    InconsistentShareIndices,
    IncorrectBatchSize,
}

#[derive(Clone)]
pub struct State<'a> {
    indices: &'a [Scalar],
    bufs: Vec<Vec<Share>>,
    count: usize,
}

impl<'a> State<'a> {
    pub fn new(indices: &'a [Scalar], b: usize) -> Self {
        let n = indices.len();
        let mut bufs = Vec::with_capacity(b);
        for _batch in 0..b {
            let mut buf = Vec::with_capacity(n);
            for index in indices.iter().cloned() {
                buf.push(Share {
                    index,
                    value: Scalar::zero(),
                });
            }
            bufs.push(buf);
        }
        State {
            indices,
            bufs,
            count: 0,
        }
    }

    fn insert_batch(&mut self, batch: Vec<Share>) -> Result<(), RKPGError> {
        use RKPGError::*;

        if batch.len() != self.bufs.len() {
            return Err(IncorrectBatchSize);
        }
        let share_index = batch.first().map(|share| share.index).ok_or(EmptyBatch)?;
        if !batch.iter().skip(1).all(|share| share.index == share_index) {
            return Err(InconsistentShareIndices);
        }
        let i = self
            .indices
            .iter()
            .position(|index| index == &share_index)
            .ok_or(IndexOutOfRange)?;

        for (share, buf) in batch.into_iter().zip(self.bufs.iter_mut()) {
            buf[i] = share;
        }
        self.count += 1;
        Ok(())
    }

    fn shares_count(&self) -> usize {
        self.count
    }
}

pub fn initial_messages_batch(vshares: &[VShare]) -> Vec<Share> {
    vshares
        .iter()
        .map(|vshare| Share {
            index: vshare.share.index,
            value: vshare.decommitment,
        })
        .collect()
}

pub fn handle_share_batch(
    state: &mut State,
    share_batch: Vec<Share>,
    rs_precompute: &Precompute,
    commitments: &[SharingCommitment],
    h: &Gej,
) -> Result<Option<Vec<Gej>>, RKPGError> {
    if share_batch.len() != commitments.len() {
        return Err(RKPGError::IncorrectBatchSize);
    }
    state.insert_batch(share_batch)?;

    let n = state.indices.len();
    let k = commitments
        .first()
        .map(|com| com.len())
        .ok_or(RKPGError::EmptyBatch)?;
    if state.shares_count() < n - k + 1 {
        return Ok(None);
    }

    let b = commitments.len();
    let mut pub_keys = Vec::with_capacity(b);
    for (buf, commitment) in state.bufs.iter().zip(commitments.iter()) {
        let it = buf.iter().map(|share| (&share.index, &share.value));
        let (poly, _errs) = rs::decode_with_precompute(rs_precompute, it, k).expect("TODO");
        let mut decommitment_neg = poly[0];
        decommitment_neg.negate_assign_mut();
        let mut pub_key = Gej::default();
        pub_key.scalar_mul(h, &decommitment_neg);
        pub_key.add_assign(&commitment[0]);
        pub_keys.push(pub_key);
    }
    Ok(Some(pub_keys))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;
    use secp256k1::scalar;

    #[test]
    fn output_public_key_is_correct() {
        let n = 10;
        let k = 3;
        let b = 3;

        let h = Gej::new_random_using_thread_rng();
        let indices = scalar::random_scalars_using_thread_rng(n);
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
            all_initial_message_batches.push(initial_messages_batch(&vshare_batch));
        }

        let mut state = State::new(&indices, b);

        let last_message_batches = all_initial_message_batches.split_off(n - k);
        for share_batch in all_initial_message_batches {
            let res =
                handle_share_batch(&mut state, share_batch, &precompute, &commitment_batch, &h);
            assert!(res.is_ok());
            assert_eq!(res.unwrap(), None);
        }

        for share_batch in last_message_batches {
            let res =
                handle_share_batch(&mut state, share_batch, &precompute, &commitment_batch, &h);
            assert!(res.is_ok());
            let opt = res.unwrap();
            assert!(opt.is_some());
            let pubkeys = opt.unwrap();
            assert_eq!(pubkeys, expected_pubkeys);
        }
    }
}
