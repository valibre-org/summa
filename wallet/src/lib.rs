use libwallet::{async_trait, ed25519, CryptoType, Vault};

pub use libwallet::{Pair, Wallet};

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

impl MatrixVault {
    pub fn new() -> Self {
        MatrixVault([0; 32])
    }
}

#[async_trait(?Send)]
impl Vault for MatrixVault {
    async fn unlock(&self, _password: &str) -> libwallet::Result<Self::Pair> {
        let pair = <Self as CryptoType>::Pair::from_seed(&self.0);
        Ok(pair)
    }
}
