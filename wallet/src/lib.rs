mod matrixconnector;


use std::convert::TryInto;

use libwallet::{async_trait, ed25519, CryptoType, Vault};

pub use libwallet::{Pair, Wallet};
use matrixconnector::{MatrixConnector, MatrixCredentials};

/// A `MatrixVault` stores in memory a private key extracted from the
/// Secure Secret Storage and Sharing system of Matrix that comes in the form of
/// a JSON object that looks like this:
/// ```json
/// {
///   "encrypted": {
///     "awesomeKeyId": {
///       "iv": "supercooliv",
///       "ciphertext": "secretciphertext",
///       "mac": "macthingy"
///     }
///   }
/// }
/// ```
pub struct MatrixVault {
    seed: Option<[u8; 32]>,
    connector: MatrixConnector,
}

impl CryptoType for MatrixVault {
    type Pair = ed25519::Pair;
}

const SEED_NAME: &str = "seed";

impl MatrixVault {
    pub fn new(username: &str, access_token: &str, server: &str) -> Self {
        MatrixVault { 
            seed: None,
            connector: MatrixConnector::new(username, access_token, server), //server: matrix.virto.community, username: test:virto.community
        } 
    }

}

#[async_trait(?Send)]
impl Vault<MatrixCredentials> for MatrixVault {
    type Pair = ed25519::Pair;

    async fn unlock(&mut self, credentials: MatrixCredentials) -> libwallet::Result<Self::Pair> {
        match self.seed {
            Some(seed) => {
                let pair = <Self as CryptoType>::Pair::from_seed(&seed);
                Ok(pair)
            } 
            None => {
                let secret = self.connector.get_secret_from_storage(SEED_NAME, &credentials).await.map_err(|_| libwallet::Error::InvalidPassword)?;
                // si storage está vacío, crear seed y guardarla en el storage
                if let Some(secret) = secret {
                    self.seed = Some(secret.try_into().map_err(|_| libwallet::Error::InvalidPassword)?);
                    let pair = <Self as CryptoType>::Pair::from_seed(&self.seed.unwrap());
                    Ok(pair)
                } else {
                    let (pair, seed) = <Self as CryptoType>::Pair::generate();
                    // guardar en storage
                    self.connector.save_secret_in_storage(SEED_NAME, &seed, &credentials).await.map_err(|_| libwallet::Error::InvalidPassword)?;
                    self.seed = Some(seed);
                    Ok(pair)
                }
            }
        }
        
    }
}
