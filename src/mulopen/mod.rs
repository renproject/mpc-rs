use secp256k1::group::Gej;
use secp256k1::scalar::Scalar;
use sha2::{Digest, Sha256};
use shamir::ped;
use shamir::sss::{self, Share};
use shamir::vss::{self, SharingCommitment, VShare};

mod zkp;

use zkp::{Response, Witness};

#[derive(Debug, Eq, PartialEq)]
pub enum MulOpenErr {
    InconsistentShares,
    InvalidShares,
    InvalidZKP,
}

#[derive(Clone, Eq, PartialEq)]
pub struct Message {
    vshare: VShare,
    commitment: Gej,
    proof: Proof,
}

pub fn initial_message_batch(
    a_vshare_batch: Vec<VShare>,
    b_vshare_batch: Vec<VShare>,
    z_vshare_batch: Vec<VShare>,
    h: &Gej,
) -> Vec<Message> {
    let b = a_vshare_batch.len();
    assert_eq!(b_vshare_batch.len(), b);
    assert_eq!(z_vshare_batch.len(), b);

    let index = a_vshare_batch
        .first()
        .expect("invalid batch size")
        .share
        .index;
    assert!(a_vshare_batch
        .iter()
        .all(|vshare| vshare.share.index == index));
    assert!(b_vshare_batch
        .iter()
        .all(|vshare| vshare.share.index == index));
    assert!(z_vshare_batch
        .iter()
        .all(|vshare| vshare.share.index == index));

    let mut message_batch = Vec::with_capacity(b);
    for batch in 0..b {
        let VShare {
            share: Share { value: alpha, .. },
            decommitment: rho,
        } = a_vshare_batch[batch];
        let VShare {
            share: Share { value: beta, .. },
            decommitment: sigma,
        } = b_vshare_batch[batch];
        let z_vshare = z_vshare_batch[batch];
        let tau = Scalar::new_random_using_thread_rng();

        let a = ped::ped_commit(h, &alpha, &rho);
        let b = ped::ped_commit(h, &beta, &sigma);
        let c = ped::ped_commit(h, &(alpha * beta), &tau);

        let witness = Witness::new(alpha, beta, rho, sigma, tau);
        let proof = prove(&witness, &a, &b, &c, h);

        let vshare = VShare {
            share: Share {
                index,
                value: (alpha * beta) + z_vshare.share.value,
            },
            decommitment: tau + z_vshare.decommitment,
        };

        message_batch.push(Message {
            vshare,
            commitment: c,
            proof,
        });
    }

    message_batch
}

pub fn handle_message_batch(
    state: &mut Vec<Vec<Share>>,
    message_batch: Vec<Message>,
    a_commitment_batch: &[SharingCommitment],
    b_commitment_batch: &[SharingCommitment],
    z_commitment_batch: &[SharingCommitment],
    h: &Gej,
) -> Result<Option<Vec<Scalar>>, MulOpenErr> {
    use MulOpenErr::*;

    let b = message_batch.len();
    assert!(b > 0);
    assert_eq!(a_commitment_batch.len(), b);
    assert_eq!(b_commitment_batch.len(), b);
    assert_eq!(z_commitment_batch.len(), b);
    assert_eq!(state.len(), b);

    let k = a_commitment_batch.first().unwrap().len();
    assert!(a_commitment_batch.iter().all(|com| com.len() == k));
    assert!(b_commitment_batch.iter().all(|com| com.len() == k));
    assert!(z_commitment_batch.iter().all(|com| com.len() == k));

    let index = message_batch[0].vshare.share.index;
    if message_batch
        .iter()
        .any(|msg| msg.vshare.share.index != index)
    {
        return Err(InconsistentShares);
    }

    if !message_batch
        .iter()
        .zip(z_commitment_batch.iter())
        .all(|(message, z_commitment)| {
            let mut com = vss::poly_eval_gej_slice_in_exponent(&z_commitment, &index);
            com.add_assign(&message.commitment);
            ped::ped_commit(h, &message.vshare.share.value, &message.vshare.decommitment) == com
        })
    {
        return Err(InvalidShares);
    }

    if !message_batch
        .iter()
        .zip(a_commitment_batch.iter().zip(b_commitment_batch.iter()))
        .all(|(message, (a_commitment, b_commitment))| {
            let a = vss::poly_eval_gej_slice_in_exponent(&a_commitment, &index);
            let b = vss::poly_eval_gej_slice_in_exponent(&b_commitment, &index);
            verify(&message.proof, &a, &b, &message.commitment, h)
        })
    {
        return Err(InvalidZKP);
    }

    for (buf, message) in state.iter_mut().zip(message_batch.iter()) {
        buf.push(message.vshare.share);
    }

    let threshold = 2 * k - 1;
    if state.first().expect("state should not be empty").len() == threshold {
        let mut secrets = Vec::with_capacity(b);
        for buf in state {
            secrets.push(sss::interpolate_shares_at_zero(buf.iter()));
        }
        return Ok(Some(secrets));
    }

    Ok(None)
}

#[derive(Clone, Eq, PartialEq)]
pub struct Proof {
    message: zkp::Message,
    response: Response,
}

pub fn prove(witness: &Witness, a: &Gej, b: &Gej, c: &Gej, h: &Gej) -> Proof {
    let (message, nonce) = zkp::message_and_nonce(b, h);
    let challenge = compute_challenge(&message, a, b, c);
    let response = zkp::response_for_challenge(&challenge, &nonce, witness);
    Proof { message, response }
}

pub fn verify(proof: &Proof, a: &Gej, b: &Gej, c: &Gej, h: &Gej) -> bool {
    let challenge = compute_challenge(&proof.message, a, b, c);
    zkp::verify_response(&proof.message, &challenge, &proof.response, h, a, b, c)
}

fn compute_challenge(message: &zkp::Message, a: &Gej, b: &Gej, c: &Gej) -> Scalar {
    let mut challenge = Scalar::default();
    let mut hasher = Sha256::new();
    let mut bs = [0_u8; 198];
    a.put_bytes(&mut bs);
    b.put_bytes(&mut bs[33..]);
    c.put_bytes(&mut bs[66..]);
    message.put_bytes(&mut bs[99..]);
    hasher.update(&bs);
    let hash = hasher.finalize();
    challenge.set_b32(hash.as_slice());
    challenge
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil;
    use secp256k1::scalar;
    use shamir::ped;

    #[test]
    fn honest_inputs_construct_valid_proofs() {
        let h = Gej::new_random_using_thread_rng();

        let alpha = Scalar::new_random_using_thread_rng();
        let beta = Scalar::new_random_using_thread_rng();
        let rho = Scalar::new_random_using_thread_rng();
        let sigma = Scalar::new_random_using_thread_rng();
        let tau = Scalar::new_random_using_thread_rng();
        let witness = Witness::new(alpha, beta, rho, sigma, tau);

        let a = ped::ped_commit(&h, &alpha, &rho);
        let b = ped::ped_commit(&h, &beta, &sigma);
        let c = ped::ped_commit(&h, &(alpha * beta), &tau);

        let proof = prove(&witness, &a, &b, &c, &h);
        assert!(verify(&proof, &a, &b, &c, &h));
    }

    #[test]
    fn output_secrets_are_the_product_of_inputs() {
        let n = 10;
        let k = 3;
        let b = 2;

        let threshold = 2 * k - 1;
        let h = Gej::new_random_using_thread_rng();
        let indices = scalar::random_scalars_using_thread_rng(n);

        let (mut a_shares_by_player, a_commitments, a_secrets, _) =
            testutil::random_sharing_batch(n, k, b, &indices, &h);
        let (mut b_shares_by_player, b_commitments, b_secrets, _) =
            testutil::random_sharing_batch(n, k, b, &indices, &h);
        let (mut z_shares_by_player, z_commitments) =
            testutil::zero_sharing_batch(n, k, b, &indices, &h);
        let mut states = Vec::with_capacity(n);
        for _player in 0..n {
            let mut state = Vec::with_capacity(b);
            for _batch in 0..b {
                state.push(Vec::with_capacity(threshold));
            }
            states.push(state);
        }

        for count in 1..=n {
            let message_batch = initial_message_batch(
                a_shares_by_player.pop().unwrap(),
                b_shares_by_player.pop().unwrap(),
                z_shares_by_player.pop().unwrap(),
                &h,
            );

            for state in states.iter_mut() {
                let res = handle_message_batch(
                    state,
                    message_batch.clone(),
                    &a_commitments,
                    &b_commitments,
                    &z_commitments,
                    &h,
                );
                if count != threshold {
                    assert_eq!(res, Ok(None));
                } else {
                    assert!(res.is_ok());
                    let opt = res.unwrap();
                    assert!(opt.is_some());
                    let outputs = opt.unwrap();
                    for ((a_secret, b_secret), output) in
                        a_secrets.iter().zip(b_secrets.iter()).zip(outputs.iter())
                    {
                        assert_eq!(output, &(a_secret * b_secret));
                    }
                }
            }
        }
    }
}
