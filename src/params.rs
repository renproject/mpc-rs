use secp256k1::group::Gej;
use secp256k1::scalar::Scalar;

pub struct Parameters {
    pub indices: Vec<Scalar>,
    pub index: Scalar,
    pub h: Gej,
}
