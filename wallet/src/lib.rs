use libwallet::{async_trait, ed25519, CryptoType, Vault};
use matrix_sdk::{ruma::UserId, Client, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::str;

use bs58;
use aes::Aes256Ctr;
use aes::cipher::{
    generic_array::GenericArray,
};
use ctr::cipher::{NewCipher, StreamCipher};
use sha2::Sha256;
use hmac::{Hmac, Mac};
use hkdf::Hkdf;
// Create alias for HMAC-SHA256
type HmacSha256 = Hmac<Sha256>;

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

pub struct MatrixSecret {
    id: String,
    key_data: KeyData,
}

#[derive(Deserialize)]
#[derive(Debug, Clone)]
pub struct KeyData {
    iv: String,
    ciphertext: String,
    mac: String
}

pub struct ByteKeyData {
    iv: [u8; 24],
    ciphertext: [u8; 60],
    mac: [u8; 44],
}

impl ByteKeyData {
    pub fn new(iv: &[u8; 24], ciphertext: &[u8; 60], mac: &[u8; 44]) -> Self {
        ByteKeyData {
            iv: *iv,
            ciphertext: *ciphertext,
            mac: *mac,
        }
    }
}

impl CryptoType for MatrixVault {
    type Pair = ed25519::Pair;
}

impl MatrixVault {
    pub fn new() -> Self {
        MatrixVault([0; 32])
    }

    // TODO: remove password
    pub async fn get_backup_key(&self, matrix_handle: &str, password: &str) -> Result<MatrixSecret> {
        let token = self.get_bearer_token(UserId::try_from(matrix_handle)?, password).await?;
        println!("Got Access Token: {}", token);
        
        let secret = self.get_backup_from_account_data(&token, matrix_handle).await;

        Ok( secret.unwrap() )
    }

    async fn get_bearer_token(&self, user: UserId, password: &str) -> Result<String> {
        println!("{:?}", user);
        let client = Client::new_from_user_id(user.clone()).await?;
    
        let access_token = client
            .login(user.localpart(), password, None, None)
            .await?
            .access_token;

        Ok(access_token)
    }

    async fn get_backup_from_account_data(&self, access_token: &str, matrix_handle: &str) -> Result<MatrixSecret> {
        // Build right url for Matrix API request
        let request_url = format!(
            //"https://matrix.org/_matrix/client/r0/user/{handle}/account_data/m.megolm_backup.v1",
            "https://matrix.virto.community/_matrix/client/r0/user/{handle}/account_data/m.megolm_backup.v1",
            handle = matrix_handle,
        );
        // Send request to Matrix API with token
        let client = reqwest::Client::new();
        let res = client
            .get(request_url)
            .bearer_auth(access_token)
            .send()
            .await?
            .json::<HashMap<String, HashMap<String, KeyData>>>()
            .await?;

        let key = MatrixSecret { 
            id: res["encrypted"].keys().next().unwrap().to_string(), 
            key_data: (*res["encrypted"].values().next().unwrap()).clone(),
        };
        
        Ok(key)
    }

    // Given the recovery key of the user, obtains the valid key and saves it 
    pub fn decode_recovery_key(&mut self, recovery_key: &str) {

        let mut key = [0u8; 35];
        let res = bs58::decode(recovery_key.split_whitespace().collect::<String>()).into(&mut key);

        // check the parity byte
        let mut parity: u8 = 0;
        for i in key {
            parity ^= i;
        }
        if parity != 0 { println!("wrong parity"); }

        // check if we have the correct header prefix
        // OLM_RECOVERY_KEY_PREFIX = [0x8B, 0x01];
        let prefix = [0x8B, 0x01];
        if key[0] != prefix[0] || key[1] != prefix[1] { println!("wrong prefix"); }

        // verify that the length of the key is correct
        if res.unwrap() - 3 != 32 { println!("wrong length"); }

        
        // strip the prefix and the parity byte to return the raw key
        let slice = &key[2 .. 34];
        self.0 = *<&[u8; 32]>::try_from(slice).unwrap();

    }

    // Validate stored key according to data in key_data
    pub fn validate_key(&self, key_data: &ByteKeyData) -> bool {
        // derive keys
        //aes key
        let zerosalt: [u8; 32] =  [0; 32];
        let hk = Hkdf::<Sha256>::new(Some(&zerosalt), &self.0);
        let mut aes_key = [0u8; 32];
        let icia = hk.expand(b"1", &mut aes_key);
        if icia.is_err() {println!("error with aes key");}
        //hmac key
        let mut hmac_key = [0u8; 32];
        let byte2: [u8; 1] = [2];
        let mut info = Vec::with_capacity(33);
        info.extend_from_slice(&aes_key);
        info.extend_from_slice(&byte2);
        let info: &[u8] = &info;
        let icia = hk.expand(info, &mut hmac_key);
        if icia.is_err() {
            println!("error with hmac key");
        }

        // encrypt ciphertext with aes-key, iv from key_data and name=""
        let nonce = base64::decode(key_data.iv.clone()).unwrap();
        let nonce = GenericArray::from_slice(&nonce);
        let key = GenericArray::from_slice(&aes_key);
        let mut cipher = Aes256Ctr::new(key.into(), nonce.into());
        let mut data = key_data.ciphertext; // to check if the key in self.0 is correct, we need to encrypt a zerosalt and then check the mac
        cipher.apply_keystream(&mut data);
        println!("key: {:?}", data);

        // compare mac from encrypt and key_data
        let mut mac = HmacSha256::new_from_slice(&hmac_key).expect("HMAC can take key of any size");
        mac.update(&data);

        let result = mac.finalize();
        let mac = result.into_bytes();
        println!("mac encrypted: {:?}", mac);
        println!("mac encoded: {}", base64::encode(mac));


        //     // stripping all the trailing = of the MACs prior comparing
        //     return info['mac'].replaceAll(RegExp(r'=+$'), '') ==
        //         encrypted.mac.replaceAll(RegExp(r'=+$'), '');

        false
    }

}

#[async_trait(?Send)]
impl Vault for MatrixVault {
    async fn unlock(&self, _password: &str) -> libwallet::Result<Self::Pair> {
        let pair = <Self as CryptoType>::Pair::from_seed(&self.0);
        Ok(pair)
    }
}

