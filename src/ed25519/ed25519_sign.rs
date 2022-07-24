use std::ops::DerefMut;
use std::sync::{Mutex, Arc};

use rand_core::{RngCore, CryptoRng};

use crate::sign::Result;
use crate::{protocol::AttenuationKeyGenerator, sign::Error};

use super::{Ed25519PrivateKey, Ed25519PublicKey};

/// [AttenuationKeygenerator] for EdDSA (ED25519) keys.
#[derive(Clone)]
pub struct EddsaKeyGen<RNG: RngCore + CryptoRng> {
    rng: Arc<Mutex<RNG>>,
}

impl<RNG: RngCore + CryptoRng> EddsaKeyGen<RNG> {
    /// Create a new EddsaKeyGen with the provided random number generator.
    pub fn new(rng: RNG) -> Self {
        EddsaKeyGen {
            rng: Arc::new(Mutex::new(rng)),
        }
    }
}

#[cfg(feature = "rng")]
impl EddsaKeyGen<rand::rngs::StdRng> {
    /// Create a new EddsaKeyGen with the standard random number generator, seeded with system entropy.
    pub fn new_with_std_rng() -> Self {
        use rand::SeedableRng;
        EddsaKeyGen {
            rng: Arc::new(Mutex::new(rand::rngs::StdRng::from_entropy())),
        }
    }
}

impl<RNG: RngCore + CryptoRng> AttenuationKeyGenerator<Ed25519PublicKey, Ed25519PrivateKey> for EddsaKeyGen<RNG> {
    fn generate_attenuation_key(&self) -> Result<(Ed25519PublicKey, Ed25519PrivateKey)> {
        let mut rng = self.rng.lock().map_err(|_| Error::CryptoError)?;
        let keypair = ed25519_dalek::Keypair::generate(rng.deref_mut());
        let pub_key = Ed25519PublicKey::new(keypair.public.clone());
        let priv_key = Ed25519PrivateKey::new("aky".to_owned(), keypair);
        Ok((pub_key, priv_key))
    }
}
