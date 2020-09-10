use secp256k1::group::Gej;
use secp256k1::scalar::Scalar;
use shamir::ped;

#[derive(Clone, Eq, PartialEq)]
pub struct Message {
    m: Gej,
    m1: Gej,
    m2: Gej,
}

impl Message {
    pub fn put_bytes(&self, bs: &mut [u8]) {
        self.m.put_bytes(bs);
        self.m1.put_bytes(&mut bs[33..]);
        self.m2.put_bytes(&mut bs[66..]);
    }
}

pub struct Nonce {
    d: Scalar,
    s: Scalar,
    x: Scalar,
    s1: Scalar,
    s2: Scalar,
}

#[derive(Clone, Eq, PartialEq)]
pub struct Response {
    y: Scalar,
    w: Scalar,
    z: Scalar,
    w1: Scalar,
    w2: Scalar,
}

pub struct Witness {
    alpha: Scalar,
    beta: Scalar,
    rho: Scalar,
    sigma: Scalar,
    tau: Scalar,
}

impl Witness {
    pub fn new(alpha: Scalar, beta: Scalar, rho: Scalar, sigma: Scalar, tau: Scalar) -> Self {
        Witness {
            alpha,
            beta,
            rho,
            sigma,
            tau,
        }
    }
}

pub fn message_and_nonce(b: &Gej, h: &Gej) -> (Message, Nonce) {
    let d = Scalar::new_random_using_thread_rng();
    let s = Scalar::new_random_using_thread_rng();
    let x = Scalar::new_random_using_thread_rng();
    let s1 = Scalar::new_random_using_thread_rng();
    let s2 = Scalar::new_random_using_thread_rng();

    let m = ped::ped_commit(h, &d, &s);
    let m1 = ped::ped_commit(h, &x, &s1);

    let mut hpow = Gej::default();
    let mut m2 = Gej::default();

    m2.scalar_mul(b, &x);
    hpow.scalar_mul(h, &s2);
    m2.add_assign(&hpow);

    (Message { m, m1, m2 }, Nonce { d, s, x, s1, s2 })
}

pub fn new_challenge() -> Scalar {
    Scalar::new_random_using_thread_rng()
}

pub fn response_for_challenge(challenge: &Scalar, nonce: &Nonce, witness: &Witness) -> Response {
    let Nonce { d, s, x, s1, s2 } = nonce;
    let Witness {
        alpha,
        beta,
        rho,
        sigma,
        tau,
    } = witness;
    let e = challenge;
    Response {
        y: d + e * beta,
        w: s + e * sigma,
        z: x + e * alpha,
        w1: s1 + e * rho,
        w2: s2 + e * (tau - sigma * alpha),
    }
}

pub fn verify_response(
    message: &Message,
    challenge: &Scalar,
    response: &Response,
    h: &Gej,
    a: &Gej,
    b: &Gej,
    c: &Gej,
) -> bool {
    let Message { m, m1, m2 } = message;
    let e = challenge;
    let Response { y, w, z, w1, w2 } = response;
    let mut tmp = Gej::default();

    let check = ped::ped_commit(h, y, w);
    tmp.scalar_mul(b, e);
    tmp.add_assign(m);
    if check != tmp {
        return false;
    }

    let check = ped::ped_commit(h, z, w1);
    tmp.scalar_mul(a, e);
    tmp.add_assign(m1);
    if check != tmp {
        return false;
    }

    let mut check = Gej::default();
    check.scalar_mul(b, z);
    tmp.scalar_mul(h, w2);
    check.add_assign(&tmp);
    tmp.scalar_mul(c, e);
    tmp.add_assign(m2);

    check == tmp
}

#[cfg(test)]
mod tests {
    use super::*;

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

        let (message, nonce) = message_and_nonce(&b, &h);
        let challenge = new_challenge();
        let response = response_for_challenge(&challenge, &nonce, &witness);
        assert!(verify_response(
            &message, &challenge, &response, &h, &a, &b, &c
        ));
    }
}
