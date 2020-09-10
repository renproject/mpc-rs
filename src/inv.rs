use secp256k1::scalar::Scalar;
use shamir::vss::VShare;

pub fn inv_transform_mulopen_output(
    mut vshare_batch: Vec<VShare>,
    mut opened_values: Vec<Scalar>,
) -> Vec<VShare> {
    for (vshare, value) in vshare_batch.iter_mut().zip(opened_values.iter_mut()) {
        value.inverse_assign();
        vshare.scale_assign_mut(value);
    }
    vshare_batch
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::mulopen;
    use crate::testutil;
    use secp256k1::group::Gej;
    use secp256k1::scalar;
    use shamir::vss;

    #[test]
    fn output_is_inversion_of_input() {
        let n = 10;
        let k = 3;
        let b = 2;

        let threshold = 2 * k - 1;
        let h = Gej::new_random_using_thread_rng();
        let indices = scalar::random_scalars_using_thread_rng(n);

        let (mut a_shares_by_player, a_commitments, a_secrets, _) =
            testutil::random_sharing_batch(n, k, b, &indices, &h);
        let (r_shares_by_player, r_commitments, _, _) =
            testutil::random_sharing_batch(n, k, b, &indices, &h);
        let (mut z_shares_by_player, z_commitments) =
            testutil::zero_sharing_batch(n, k, b, &indices, &h);
        let mut r_shares_by_player_input = r_shares_by_player.clone();
        let mut inv_secrets = Vec::with_capacity(b);
        for secret in a_secrets.iter() {
            let mut inv = Scalar::default();
            inv.inverse(secret);
            inv_secrets.push(inv);
        }
        let mut states = Vec::with_capacity(n);
        for _player in 0..n {
            let mut state = Vec::with_capacity(b);
            for _batch in 0..b {
                state.push(Vec::with_capacity(threshold));
            }
            states.push(state);
        }
        let mut player_outputs = Vec::with_capacity(n);

        for count in 1..=n {
            let message_batch = mulopen::initial_message_batch(
                a_shares_by_player.pop().unwrap(),
                r_shares_by_player_input.pop().unwrap(),
                z_shares_by_player.pop().unwrap(),
                &h,
            );

            for (state, r_shares) in states
                .iter_mut()
                .zip(r_shares_by_player.clone().into_iter())
            {
                let res = mulopen::handle_message_batch(
                    state,
                    message_batch.clone(),
                    &a_commitments,
                    &r_commitments,
                    &z_commitments,
                    &h,
                )
                .map(|opt| opt.map(|secrets| inv_transform_mulopen_output(r_shares, secrets)));
                if count != threshold {
                    assert_eq!(res, Ok(None));
                } else {
                    assert!(res.is_ok());
                    let opt = res.unwrap();
                    assert!(opt.is_some());
                    player_outputs.push(opt.unwrap());
                }
            }
        }

        let output_sharings = testutil::transpose(player_outputs);
        for (sharing, a_inv) in output_sharings.iter().zip(inv_secrets.iter()) {
            let (output, _) = vss::interpolate_shares_at_zero(sharing.iter());
            assert_eq!(&output, a_inv);
        }
    }
}
