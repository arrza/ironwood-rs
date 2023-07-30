use log::debug;
use sodiumoxide::crypto::box_::{self, PublicKey, SecretKey};
use sodiumoxide::crypto::sign::ed25519;

use crate::network::crypto::PublicKeyBytes;

/********
 * util *
 ********/

fn bytes_equal(a: &[u8], b: &[u8]) -> bool {
    a == b
}

fn bytes_push(dest: &mut [u8], source: &[u8], offset: usize) -> usize {
    dest[offset..offset + source.len()].copy_from_slice(source);
    offset + source.len()
}

fn bytes_pop(dest: &mut [u8], source: &[u8], offset: usize) -> usize {
    dest.copy_from_slice(&source[offset..offset + dest.len()]);
    offset + dest.len()
}

/******
 * ed *
 ******/

pub const ED_PUB_SIZE: usize = 32;
pub const ED_PRIV_SIZE: usize = 64;
pub const ED_SIG_SIZE: usize = 64;

pub type EdPub = ed25519::PublicKey;
pub type EdPriv = ed25519::SecretKey;
pub type EdSig = [u8; ED_SIG_SIZE];

pub fn ed_sign(msg: &[u8], priv_key: &EdPriv) -> EdSig {
    let signature = ed25519::sign_detached(msg, &priv_key);
    signature.to_bytes()
}

pub fn ed_check(msg: &[u8], sig: &EdSig, pub_key: &EdPub) -> bool {
    let signature = ed25519::Signature::from_bytes(sig).unwrap();
    ed25519::verify_detached(&signature, msg, &pub_key)
}

pub fn to_box(pub_key: &EdPub) -> BoxPub {
    let curve25519_pk = sodiumoxide::crypto::sign::ed25519::to_curve25519_pk(&pub_key)
        .map_err(|e| {
            debug!(
                "Invalid Public Key: {:?} pk: {}",
                e,
                PublicKeyBytes(pub_key.0)
            )
        })
        .unwrap();
    curve25519_pk
}

pub fn to_box_priv(priv_key: &EdPriv) -> BoxPriv {
    let curve25519_sk = sodiumoxide::crypto::sign::ed25519::to_curve25519_sk(&priv_key).unwrap();
    curve25519_sk
}

pub fn pub_from_priv(priv_key: &EdPriv) -> EdPub {
    let public_key = ed25519::PublicKey::from_slice(&priv_key[32..]).unwrap();
    public_key
}

/*******
 * box *
 *******/

pub const BOX_PUB_SIZE: usize = 32;
pub const BOX_PRIV_SIZE: usize = 32;
pub const BOX_SHARED_SIZE: usize = 32;
pub const BOX_NONCE_SIZE: usize = 24;
pub const BOX_OVERHEAD: usize = 16; // TagSize is the size, in bytes, of a poly1305 authenticator.

pub type BoxPub = PublicKey;
pub type BoxPriv = SecretKey;
pub type BoxShared = [u8; BOX_SHARED_SIZE];
pub type BoxNonce = [u8; BOX_NONCE_SIZE];

pub fn new_box_keys() -> (BoxPub, BoxPriv) {
    let (pk, sk) = box_::gen_keypair();
    (pk, sk)
}

pub fn get_shared(pub_key: &BoxPub, priv_key: &BoxPriv) -> BoxShared {
    let shared = box_::precompute(&pub_key, &priv_key);
    shared.0
}

pub fn box_open(out: &mut [u8], boxed: &[u8], nonce: u64, shared: &BoxShared) -> Result<(), ()> {
    let nonce_array = nonce_for_uint64(nonce);
    let nonce = box_::Nonce::from_slice(&nonce_array).unwrap();
    let shared_key = box_::PrecomputedKey::from_slice(shared).unwrap();
    let res = box_::open_precomputed(boxed, &nonce, &shared_key)?;
    out.copy_from_slice(&res);
    Ok(())
}

pub fn box_seal(msg: &[u8], nonce: u64, shared: &BoxShared) -> Vec<u8> {
    let nonce_array = nonce_for_uint64(nonce);
    let nonce = box_::Nonce::from_slice(&nonce_array).unwrap();
    let shared_key = box_::PrecomputedKey::from_slice(shared).unwrap();
    let boxed_msg = box_::seal_precomputed(msg, &nonce, &shared_key);
    boxed_msg
}

pub fn nonce_for_uint64(u64: u64) -> BoxNonce {
    let mut nonce = [0u8; BOX_NONCE_SIZE];
    let slice = &mut nonce[BOX_NONCE_SIZE - 8..];
    slice.copy_from_slice(&u64.to_be_bytes());
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::{PublicKey, SecretKey};
    use rand::rngs::OsRng;

    #[test]
    fn test_ed_x25519() {
        let (bs_pub, bs_priv) = ed25519::gen_keypair();
        let e_pub = EdPub::from_slice(&bs_pub[..]).unwrap();
        let e_priv = EdPriv::from_slice(&bs_priv[..]).unwrap();

        let pub1 = to_box(&e_pub);
        let priv1 = to_box_priv(&e_priv);
        let (pub2, priv2) = new_box_keys();
        let enc_shared = get_shared(&pub1, &priv2);
        let dec_shared = get_shared(&pub2, &priv1);

        assert_eq!(enc_shared, dec_shared);
    }

    #[test]
    fn test_ed_x25519_go() {
        let bs_pub = [
            44, 236, 247, 231, 6, 142, 167, 205, 127, 66, 144, 34, 129, 18, 13, 59, 224, 109, 241,
            229, 139, 246, 227, 40, 83, 223, 158, 208, 239, 217, 113, 108,
        ];
        let bs_priv = [
            189, 197, 96, 28, 228, 168, 70, 98, 115, 136, 129, 235, 177, 202, 181, 1, 25, 103, 247,
            57, 191, 204, 189, 152, 181, 139, 211, 21, 171, 81, 22, 88, 44, 236, 247, 231, 6, 142,
            167, 205, 127, 66, 144, 34, 129, 18, 13, 59, 224, 109, 241, 229, 139, 246, 227, 40, 83,
            223, 158, 208, 239, 217, 113, 108,
        ];

        let e_pub = EdPub::from_slice(&bs_pub).unwrap();
        let e_priv = EdPriv::from_slice(&bs_priv).unwrap();

        let pub1 = to_box(&e_pub);
        let priv1 = to_box_priv(&e_priv);
        //let (pub2, priv2) = new_box_keys();
        let pub2 = BoxPub::from_slice(&[
            156, 25, 129, 18, 208, 115, 19, 103, 46, 228, 153, 118, 178, 120, 54, 115, 10, 138, 97,
            211, 146, 210, 244, 139, 197, 159, 109, 15, 137, 65, 176, 2,
        ])
        .unwrap();
        let priv2 = BoxPriv::from_slice(&[
            186, 183, 171, 47, 100, 151, 9, 32, 102, 5, 226, 106, 123, 239, 174, 223, 187, 43, 33,
            217, 138, 93, 112, 43, 193, 160, 43, 44, 59, 254, 153, 68,
        ])
        .unwrap();
        let enc_shared = get_shared(&pub1, &priv2);
        let dec_shared = get_shared(&pub2, &priv1);

        assert_eq!(enc_shared, dec_shared);
        assert_eq!(
            enc_shared,
            [
                105, 87, 88, 57, 52, 249, 99, 32, 66, 76, 111, 16, 100, 91, 168, 110, 235, 5, 112,
                101, 130, 234, 110, 212, 201, 172, 188, 161, 165, 251, 252, 49
            ]
        );
    }
}
