mod matrixconnector;


use std::convert::TryInto;

use libwallet::{async_trait, ed25519, CryptoType, Vault};

pub use libwallet::{Pair, Wallet};
use matrixconnector::MatrixConnector;

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
pub struct MatrixVault([u8; 32]);

impl CryptoType for MatrixVault {
    type Pair = ed25519::Pair;
}

const SEED_NAME: &str = "seed";

impl MatrixVault {
    pub fn new() -> Self {
        MatrixVault([0; 32])
    }

    // try to recover key from matrix
    pub async fn new_from_keyfile(username: &str, password: &str, storage_key: &str) -> Result<Self> {
        let mut vault = MatrixVault([0; 32]);
        let matrix_connector = MatrixConnector::connect(username, password).await.unwrap();
        let secret = matrix_connector.get_secret_using_keyfile(SEED_NAME, storage_key).await.unwrap();
        vault.0 = secret.try_into().unwrap(); // TODO: remove unwrap

        Ok(vault)
    }

}

#[async_trait(?Send)]
impl Vault for MatrixVault {
    async fn unlock(&self, _password: &str) -> libwallet::Result<Self::Pair> {
        let pair = <Self as CryptoType>::Pair::from_seed(&self.0);
        Ok(pair)
    }
}


pub type Result<T> = core::result::Result<T, Error>;

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum Error {
    #[cfg_attr(feature = "std", error("Connection to Matrix server failed"))]
    ConnectionFailed,
}