use core::fmt;

use ed25519_dalek::{Keypair, PublicKey, SecretKey, Signature, Signer, Verifier};

use crate::types::Addr;

pub const PUBLIC_KEY_SIZE: usize = 32;
pub const PRIVATE_KEY_SIZE: usize = 64;
pub const SIGNATURE_SIZE: usize = 64;

#[derive(PartialEq, Eq, Hash, Clone)]
pub struct PublicKeyBytes(pub [u8; PUBLIC_KEY_SIZE]);

impl fmt::Debug for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl fmt::Display for PublicKeyBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl PublicKeyBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn to_bytes(&self) -> [u8; PUBLIC_KEY_SIZE] {
        self.0.clone()
    }

    pub fn verify(&self, message: &[u8], sig: &[u8]) -> bool {
        // Convert the PublicKeyBytes to a dalek PublicKey
        let pub_key = PublicKey::from_bytes(&self.0).unwrap();

        // Convert the bytes to a dalek Signature
        let signature = Signature::from_bytes(sig).unwrap();

        // Use the verify method from the `Verifier` trait
        pub_key.verify(message, &signature).is_ok()
    }
}

impl Into<Addr> for PublicKeyBytes {
    fn into(self) -> Addr {
        Addr(self)
    }
}

impl From<PublicKey> for PublicKeyBytes {
    fn from(pk: PublicKey) -> Self {
        PublicKeyBytes(pk.to_bytes())
    }
}

impl Into<PublicKey> for PublicKeyBytes {
    fn into(self) -> PublicKey {
        PublicKey::from_bytes(&self.0).unwrap()
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct PrivateKeyBytes(pub [u8; PRIVATE_KEY_SIZE]);

impl PrivateKeyBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    pub fn sign(&self, message: &[u8]) -> SignatureBytes {
        // Convert the PrivateKeyBytes to a dalek SecretKey
        let secret_key = SecretKey::from_bytes(&self.0[..32]).unwrap();

        // Create a Keypair from the SecretKey
        let public_key = PublicKey::from_bytes(&self.0[32..]).unwrap();
        let keypair = Keypair {
            secret: secret_key,
            public: public_key,
        };

        // Use the sign method from the `Signer` trait
        let signature = keypair.sign(message);

        // Return the signature as a byte vector
        SignatureBytes(signature.to_bytes())
    }
}

#[derive(Debug, PartialEq, Eq, Hash, Clone)]
pub struct SignatureBytes(pub [u8; SIGNATURE_SIZE]);

impl SignatureBytes {
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl fmt::Display for SignatureBytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", hex::encode(self.0))
    }
}

impl Default for SignatureBytes {
    fn default() -> Self {
        Self([0; SIGNATURE_SIZE])
    }
}

#[derive(Debug)]
pub struct Crypto {
    pub private_key: PrivateKeyBytes,
    pub public_key: PublicKeyBytes,
}

impl Crypto {
    pub fn new(secret: &SecretKey) -> Self {
        let pk: PublicKey = secret.into();
        let mut private_key = PrivateKeyBytes([0; PRIVATE_KEY_SIZE]);
        private_key.0[..32].copy_from_slice(secret.as_bytes());
        private_key.0[32..].copy_from_slice(pk.as_bytes());
        let public_key = PublicKeyBytes(pk.to_bytes());
        Crypto {
            private_key,
            public_key,
        }
    }

    // Add any additional methods you need for Crypto here
}

impl PublicKeyBytes {
    pub fn equal(&self, compared_key: &Self) -> bool {
        self == compared_key
    }

    pub fn addr(&self) -> Addr {
        Addr(self.clone())
    }
}

impl PrivateKeyBytes {
    pub fn equal(&self, compared_key: &Self) -> bool {
        self == compared_key
    }
}
