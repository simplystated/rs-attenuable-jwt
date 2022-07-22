use ring::signature::{Ed25519KeyPair, KeyPair};

use crate::sign::Result;
use crate::{protocol::AttenuationKeyGenerator, sign::Error};

use super::{Ed25519PrivateKey, Ed25519PublicKey};

/// [AttenuationKeygenerator] for EdDSA (ED25519) keys.
#[derive(Clone)]
pub struct EddsaKeyGen;

impl AttenuationKeyGenerator<Ed25519PublicKey, Ed25519PrivateKey> for EddsaKeyGen {
    fn generate_attenuation_key(&self) -> Result<(Ed25519PublicKey, Ed25519PrivateKey)> {
        use ring::rand::SystemRandom;

        let rng = SystemRandom::new();
        let pkcs8_bytes =
            Ed25519KeyPair::generate_pkcs8(&rng).map_err(|_| Error::KeyError(None))?;
        let key_pair =
            Ed25519KeyPair::from_pkcs8(pkcs8_bytes.as_ref()).map_err(|_| Error::KeyError(None))?;
        let pub_key = Ed25519PublicKey::new(key_pair.public_key().as_ref().to_vec());
        let priv_key = Ed25519PrivateKey::new("aky".to_owned(), pkcs8_bytes.as_ref());
        Ok((pub_key, priv_key))
    }
}
