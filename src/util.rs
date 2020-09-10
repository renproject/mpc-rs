use shamir::vss::VShare;

pub fn all_indices_equal_in_vshare_batch(vshares: &[VShare]) -> bool {
    vshares
        .windows(2)
        .all(|w| w[0].share.index == w[1].share.index)
}
