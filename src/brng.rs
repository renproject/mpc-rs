use secp256k1::scalar::Scalar;
use shamir::vss::{self, SharingCommitment, VShare, VSharing};

use crate::params::Parameters;

#[derive(Debug, PartialEq)]
pub enum BRNGError {
    WrongNumberOfContributions,
    InvalidCommitments,
    WrongIndex,
    InvalidShare,
}

pub fn create_sharing_batch(b: usize, k: usize, params: &Parameters) -> Vec<VSharing> {
    let mut sharing_batch = Vec::with_capacity(b);
    for _ in 0..b {
        let (vshares, commitment) = vss::vshare_secret(
            &params.h,
            &params.indices,
            &Scalar::new_random_using_thread_rng(),
            k,
        );
        sharing_batch.push(VSharing {
            vshares,
            commitment,
        });
    }
    sharing_batch
}

pub fn is_valid<'a, I, J>(
    k: usize,
    params: &Parameters,
    vshare_commitment_pairs_batch: I,
) -> Result<(), BRNGError>
where
    I: Iterator<Item = J> + Clone,
    J: Iterator<Item = (&'a VShare, &'a SharingCommitment)> + ExactSizeIterator + Clone,
{
    use BRNGError::*;

    for vshare_commitment_pairs in vshare_commitment_pairs_batch.clone() {
        if vshare_commitment_pairs.len() != k {
            return Err(WrongNumberOfContributions);
        }
        if !vshare_commitment_pairs
            .clone()
            .all(|(_, commitment)| commitment.len() == k)
        {
            return Err(InvalidCommitments);
        }
        if !vshare_commitment_pairs
            .clone()
            .all(|(vshare, _)| vshare.share.index == params.index)
        {
            return Err(WrongIndex);
        }
    }
    for mut vshare_commitment_pairs in vshare_commitment_pairs_batch {
        if !vshare_commitment_pairs
            .all(|(vshare, commitment)| vss::vshare_is_valid(vshare, commitment, &params.h))
        {
            return Err(InvalidShare);
        }
    }

    Ok(())
}

pub fn output_sharing_batch<'a, I, J>(
    vshare_commitment_pairs: I,
) -> (Vec<VShare>, Vec<SharingCommitment>)
where
    I: Iterator<Item = J> + ExactSizeIterator,
    J: Iterator<Item = (&'a VShare, &'a SharingCommitment)>,
{
    vshare_commitment_pairs.map(sum_sharing).unzip()
}

fn sum_sharing<'a, I>(mut vshare_commitment_pairs: I) -> (VShare, SharingCommitment)
where
    I: Iterator<Item = (&'a VShare, &'a SharingCommitment)>,
{
    let (initial_vshare, initial_commitment) = vshare_commitment_pairs.next().unwrap();
    vshare_commitment_pairs.fold(
        (initial_vshare.clone(), initial_commitment.clone()),
        |(mut acc_vshare, mut acc_commitment), (vshare, commitment)| {
            acc_vshare.add_assign_mut(vshare);
            acc_commitment.add_assign_mut(commitment);
            (acc_vshare, acc_commitment)
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use secp256k1::scalar::Scalar;
    use shamir::sss::Share;

    #[test]
    fn output_shares_and_commitments_are_summed() {
        let k = 5;
        let b = 3;

        let index = Scalar::new_random_using_thread_rng();

        let mut vshare_sums = Vec::with_capacity(b);
        let mut commitment_sums = Vec::with_capacity(b);
        let mut vshare_batches = Vec::with_capacity(b);
        let mut commitment_batches = Vec::with_capacity(b);
        for _ in 0..b {
            vshare_sums.push(VShare {
                share: Share {
                    index,
                    value: Scalar::zero(),
                },
                decommitment: Scalar::zero(),
            });
            commitment_sums.push(shamir::testutil::zero_commitment(k));
            vshare_batches.push(Vec::with_capacity(k));
            commitment_batches.push(Vec::with_capacity(k));
        }
        for ((vshare_batch, commitment_batch), (vshare_sum, commitment_sum)) in vshare_batches
            .iter_mut()
            .zip(commitment_batches.iter_mut())
            .zip(vshare_sums.iter_mut().zip(commitment_sums.iter_mut()))
        {
            for _ in 0..k {
                let value = Scalar::new_random_using_thread_rng();
                let decommitment = Scalar::new_random_using_thread_rng();
                let vshare = VShare {
                    share: Share { index, value },
                    decommitment,
                };
                vshare_batch.push(vshare);
                vshare_sum.add_assign_mut(&vshare);

                let commitment = shamir::testutil::random_commitment_using_thread_rng(k);
                commitment_sum.add_assign_mut(&commitment);
                commitment_batch.push(commitment);
            }
        }

        let (output_shares, output_commitments) = output_sharing_batch(
            vshare_batches
                .iter()
                .zip(commitment_batches.iter())
                .map(|(s, c)| s.iter().zip(c.iter())),
        );

        for (vshare, check) in output_shares.iter().zip(vshare_sums.iter()) {
            assert_eq!(vshare, check);
        }
        for (commitment, check) in output_commitments.iter().zip(commitment_sums.iter()) {
            assert_eq!(commitment, check);
        }
    }
}
