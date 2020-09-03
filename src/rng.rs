use crate::open::{self, OpenError};
use crate::params::Parameters;
use secp256k1::group::Gej;
use secp256k1::scalar::Scalar;
use shamir::sss::Share;
use shamir::vss::{SharingCommitment, VShare};

pub struct DirectedVShare {
    pub vshare: VShare,
    pub to: Scalar,
}

macro_rules! impl_rxg_initial_messages {
    ($i:ident, $j:ident) => {
        pub fn $i(
            coeff_shares_batch: &[Vec<VShare>],
            indices: &[Scalar],
        ) -> Vec<Vec<DirectedVShare>> {
            let n = indices.len();
            let b = coeff_shares_batch.len();
            let mut directed_vshares_batch = Vec::with_capacity(n);
            for _player in 0..n {
                directed_vshares_batch.push(Vec::with_capacity(b));
            }
            for coeff_shares in coeff_shares_batch {
                let messages = $j(coeff_shares.iter(), indices);
                for (i, message) in messages.into_iter().enumerate() {
                    directed_vshares_batch[i].push(message);
                }
            }
            directed_vshares_batch
        }
    };
}

impl_rxg_initial_messages!(initial_messages_batch_rng, shares_of_shares_rng);
impl_rxg_initial_messages!(initial_messages_batch_rzg, shares_of_shares_rzg);

macro_rules! impl_rxg_own_commitment {
    ($i:ident, $j:ident) => {
        pub fn $i(
            coeff_commitments_batch: &[Vec<SharingCommitment>],
            own_index: &Scalar,
        ) -> Vec<SharingCommitment> {
            let b = coeff_commitments_batch.len();
            let mut own_commitment_batch = Vec::with_capacity(b);
            for coeff_commitments in coeff_commitments_batch {
                own_commitment_batch.push($j(coeff_commitments.iter(), own_index));
            }

            own_commitment_batch
        }
    };
}

impl_rxg_own_commitment!(own_commitment_batch_rng, commitment_for_own_share_rng);
impl_rxg_own_commitment!(own_commitment_batch_rzg, commitment_for_own_share_rzg);

macro_rules! impl_rxg_output_commitment {
    ($i:ident, $j:ident) => {
        pub fn $i(coeff_commitments_batch: &[Vec<SharingCommitment>]) -> Vec<SharingCommitment> {
            let b = coeff_commitments_batch.len();
            let mut output_commitment_batch = Vec::with_capacity(b);
            for coeff_commitments in coeff_commitments_batch {
                // TODO: This allows each of the vectors of commitments to have different lengths;
                // should this be allowed?
                output_commitment_batch.push($j(coeff_commitments.iter()));
            }
            output_commitment_batch
        }
    };
}

impl_rxg_output_commitment!(output_commitment_batch_rng, output_commitment_rng);
impl_rxg_output_commitment!(output_commitment_batch_rzg, output_commitment_rzg);

fn output_commitment_rng<'a, I>(coeff_commitments: I) -> SharingCommitment
where
    I: Iterator<Item = &'a SharingCommitment> + ExactSizeIterator,
{
    let k = coeff_commitments.len();
    let mut output_commitment = SharingCommitment::with_capacity(k);
    for coeff_commitment in coeff_commitments {
        output_commitment.push(coeff_commitment[0])
    }
    output_commitment
}

fn output_commitment_rzg<'a, I>(coeff_commitments: I) -> SharingCommitment
where
    I: Iterator<Item = &'a SharingCommitment> + ExactSizeIterator,
{
    let k = coeff_commitments.len() + 1;
    let mut output_commitment = SharingCommitment::with_capacity(k);
    output_commitment.push(Gej::infinity());
    for coeff_commitment in coeff_commitments {
        output_commitment.push(coeff_commitment[0])
    }
    output_commitment
}

fn shares_of_shares_rng<'a, I>(coeff_shares: I, indices: &[Scalar]) -> Vec<DirectedVShare>
where
    I: Iterator<Item = &'a VShare> + DoubleEndedIterator + Clone,
{
    let n = indices.len();
    let mut shares_of_shares = Vec::with_capacity(n);
    for index in indices {
        let vshare = poly_eval_vshares(coeff_shares.clone(), index);
        shares_of_shares.push(DirectedVShare { vshare, to: *index });
    }
    shares_of_shares
}

fn shares_of_shares_rzg<'a, I>(coeff_shares: I, indices: &[Scalar]) -> Vec<DirectedVShare>
where
    I: Iterator<Item = &'a VShare> + DoubleEndedIterator + Clone,
{
    let n = indices.len();
    let mut shares_of_shares = Vec::with_capacity(n);
    for index in indices {
        let mut vshare = poly_eval_vshares(coeff_shares.clone(), index);
        vshare.scale_assign_mut(index);
        shares_of_shares.push(DirectedVShare { vshare, to: *index });
    }
    shares_of_shares
}

fn poly_eval_vshares<'a, I>(vshares: I, index: &Scalar) -> VShare
where
    I: Iterator<Item = &'a VShare> + DoubleEndedIterator,
{
    let mut vshares = vshares.rev();
    // NOTE: This unwrap seems fine because we probably don't ever want to call this function with
    // an empty iterator and have it then return a default value without otherwise signalling that
    // the function is being used incorrectly. A panic therefore seems appropriate in this case.
    let mut eval_vshare = *vshares.next().unwrap();
    for vshare in vshares {
        eval_vshare.scale_assign_mut(index);
        eval_vshare.add_assign_mut(vshare);
    }
    eval_vshare
}

fn commitment_for_own_share_rng<'a, I>(commitments: I, index: &Scalar) -> SharingCommitment
where
    I: Iterator<Item = &'a SharingCommitment> + DoubleEndedIterator,
{
    let mut commitments = commitments.rev();
    // NOTE: This unwrap seems fine because we probably don't ever want to call this function with
    // an empty iterator and have it then return a default value without otherwise signalling that
    // the function is being used incorrectly. A panic therefore seems appropriate in this case.
    let mut eval_commitment = commitments.next().unwrap().clone();
    for commitment in commitments {
        eval_commitment.scale_assign_mut(index);
        eval_commitment.add_assign_mut(commitment);
    }
    eval_commitment
}

fn commitment_for_own_share_rzg<'a, I>(commitments: I, index: &Scalar) -> SharingCommitment
where
    I: Iterator<Item = &'a SharingCommitment> + DoubleEndedIterator,
{
    let mut commitments = commitments.rev();
    // NOTE: This unwrap seems fine because we probably don't ever want to call this function with
    // an empty iterator and have it then return a default value without otherwise signalling that
    // the function is being used incorrectly. A panic therefore seems appropriate in this case.
    let mut eval_commitment = commitments.next().unwrap().clone();
    for commitment in commitments {
        eval_commitment.scale_assign_mut(index);
        eval_commitment.add_assign_mut(commitment);
    }
    eval_commitment.scale_assign_mut(index);
    eval_commitment
}

pub fn handle_directed_vshare_batch(
    state: &mut open::State,
    inst_params: &open::InstanceParams,
    params: &Parameters,
    directed_vshare_batch: Vec<DirectedVShare>,
) -> Result<Option<Vec<VShare>>, OpenError> {
    let vshare_batch = directed_vshare_batch
        .into_iter()
        .map(|DirectedVShare { vshare, .. }| vshare)
        .collect();
    Ok(state
        .handle_vshare_batch(inst_params, params, vshare_batch)?
        .map(|values| {
            let mut output_vshares = Vec::with_capacity(values.len());
            for (value, decommitment) in values {
                output_vshares.push(VShare {
                    share: Share {
                        index: params.index,
                        value,
                    },
                    decommitment,
                });
            }
            output_vshares
        }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::open::{InstanceParams, State};
    use crate::params::Parameters;
    use crate::testutil;
    use secp256k1::scalar;
    use shamir::vss;

    fn params_and_state(
        indices: &[Scalar],
        h: Gej,
        inst_params: &[InstanceParams],
    ) -> (Vec<Parameters>, Vec<State>) {
        let n = indices.len();
        let mut player_params = Vec::with_capacity(n);
        for index in indices.iter() {
            player_params.push(Parameters {
                indices: indices.to_vec(),
                index: *index,
                h,
            });
        }
        let mut states = Vec::with_capacity(n);
        for inst_params in inst_params.iter() {
            states.push(State::new(inst_params));
        }

        (player_params, states)
    }

    #[test]
    fn rng_produces_valid_sharing() {
        let n = 10;
        let k = 5;
        let b = 3;

        let h = Gej::new_random_using_thread_rng();
        let indices = scalar::random_scalars_using_thread_rng(n);
        let (mut inputs_by_player, commitments) = testutil::rxg_inputs(k, b, &indices, &h);
        let output_commitments = output_commitment_batch_rng(&commitments);

        let mut player_inst_params = Vec::with_capacity(n);
        for index in indices.iter() {
            player_inst_params.push(InstanceParams::new(own_commitment_batch_rng(
                &commitments,
                index,
            )));
        }
        let (player_params, mut states) = params_and_state(&indices, h, &player_inst_params);

        for index in indices.iter().take(k - 1) {
            let messages =
                initial_messages_batch_rng(&inputs_by_player.remove(index).unwrap(), &indices);
            for (i, message) in messages.into_iter().enumerate() {
                let res = handle_directed_vshare_batch(
                    &mut states[i],
                    &player_inst_params[i],
                    &player_params[i],
                    message,
                );
                assert!(res.is_ok());
            }
        }

        let messages =
            initial_messages_batch_rng(&inputs_by_player.remove(&indices[k]).unwrap(), &indices);
        for (i, message) in messages.into_iter().enumerate() {
            let res = handle_directed_vshare_batch(
                &mut states[i],
                &player_inst_params[i],
                &player_params[i],
                message,
            );
            assert!(res.is_ok());
            let res = res.unwrap();
            assert!(res.is_some());
            let vshares = res.unwrap();
            for (vshare, commitment) in vshares.iter().zip(output_commitments.iter()) {
                assert!(vss::vshare_is_valid(vshare, commitment, &h));
            }
        }
    }

    #[test]
    fn rzg_produces_valid_sharing() {
        let n = 10;
        let k = 5;
        let b = 3;

        let h = Gej::new_random_using_thread_rng();
        let indices = scalar::random_scalars_using_thread_rng(n);
        let (mut inputs_by_player, commitments) = testutil::rxg_inputs(k, b, &indices, &h);
        let output_commitments = output_commitment_batch_rzg(&commitments);

        let mut player_inst_params = Vec::with_capacity(n);
        for index in indices.iter() {
            player_inst_params.push(InstanceParams::new(own_commitment_batch_rzg(
                &commitments,
                index,
            )));
        }
        let (player_params, mut states) = params_and_state(&indices, h, &player_inst_params);

        for index in indices.iter().take(k - 1) {
            let messages =
                initial_messages_batch_rzg(&inputs_by_player.remove(index).unwrap(), &indices);
            for (i, message) in messages.into_iter().enumerate() {
                let res = handle_directed_vshare_batch(
                    &mut states[i],
                    &player_inst_params[i],
                    &player_params[i],
                    message,
                );
                assert!(res.is_ok());
            }
        }

        let mut all_shares = Vec::<Vec<_>>::with_capacity(b);
        all_shares.resize_with(b, || vec![]);
        let messages =
            initial_messages_batch_rzg(&inputs_by_player.remove(&indices[k]).unwrap(), &indices);
        for (i, message) in messages.into_iter().enumerate() {
            let res = handle_directed_vshare_batch(
                &mut states[i],
                &player_inst_params[i],
                &player_params[i],
                message,
            );
            assert!(res.is_ok());
            let res = res.unwrap();
            assert!(res.is_some());
            let vshares = res.unwrap();
            for (vshare, commitment) in vshares.iter().zip(output_commitments.iter()) {
                assert!(vss::vshare_is_valid(vshare, commitment, &h));
            }

            for (i, vshare) in vshares.into_iter().enumerate() {
                all_shares[i].push(vshare);
            }
        }

        for sharing in all_shares {
            let (secret, _) = vss::interpolate_shares_at_zero(sharing.iter());
            assert!(secret.is_zero());
        }
    }
}
