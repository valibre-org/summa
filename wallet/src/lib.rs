use libwallet::{async_trait, ed25519, CryptoType, Vault};
use matrix_sdk::{ruma::UserId, Client, Result};
use serde::Deserialize;
use std::collections::HashMap;
use std::convert::TryFrom;

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

    // remove password
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

        //   don't forget to strip all spaces before base58 decoding!
        //   final result = base58.decode(recoveryKey.replaceAll(' ', ''));
        let mut key = [0u8; 35];
        let res = bs58::decode(recovery_key.split_whitespace().collect::<String>()).into(&mut key);
   
        //   // check the parity byte
        //   var parity = 0;
        //   for (final b in result) {
        //     parity ^= b;
        //   }
        //   // as we xor'd ALL the bytes, including the parity byte, the result should be zero!
        //   if (parity != 0) {
        //     throw 'Incorrect parity';
        //   }

        //   // check if we have the correct header prefix
        //   var OLM_RECOVERY_KEY_PREFIX = [0x8B, 0x01];
        //   for (var i = 0; i < OLM_RECOVERY_KEY_PREFIX.length; i++) {
        //     if (result[i] != OLM_RECOVERY_KEY_PREFIX[i]) {
        //       throw 'Incorrect prefix';
        //     }
        //   }

        //   // verify that the length of the key is correct
        //   var OLM_PRIVATE_KEY_LENGTH = 32; // can also be fetched from olm somehow...
        //   if (result.length !=
        //       OLM_RECOVERY_KEY_PREFIX.length + OLM_PRIVATE_KEY_LENGTH + 1) {
        //     throw 'Incorrect length';
        //   }
        //println!("len {}", res.unwrap());
        if res.unwrap() - 3 == 32 {
            println!("Correct length");
        }

        
        //   // and finally, strip the prefix and the parity byte to return the raw key
        //   return Uint8List.fromList(result.sublist(OLM_RECOVERY_KEY_PREFIX.length,
        //       OLM_RECOVERY_KEY_PREFIX.length + OLM_PRIVATE_KEY_LENGTH));
        let slice = &key[2 .. key.len() - 1];
        println!("len: {}", slice.len());
        let array = <&[u8; 32]>::try_from(slice).unwrap();
        self.0 = *array;
    }

    // Validate stored key according to data in key_data
    pub fn validate_key(&self, key_data: &ByteKeyData) -> bool {

        //     // ZERO_STR are 32 bytes of zero. We encrypt with our generated key, a blank name and the iv of the event
        let aes_key = self.get_aes_key();
        //let key = GenericArray::from_slice(aes_key.finalize().into_bytes());
        let zerosalt: [u8; 32] =  [0; 32];
        let hk = Hkdf::<Sha256>::new(Some(&zerosalt), &self.0);
        let mut okm = [0u8; 42];
        hk.expand(b"1", &mut okm);
        let nonce = base64::decode(key_data.iv.clone()).unwrap();
        let nonce = GenericArray::from_slice(&nonce);
        println!("have nonce");
        
        //     var encrypted = encryptAes(ZERO_STR, key, '', info['iv']);
        // create cipher instance
        //let mut cipher = Aes256Ctr::new(GenericArray::from_slice(&okm), nonce.into());
        let mut cipher = Aes256Ctr::new(GenericArray::from_slice(&aes_key.finalize().into_bytes()), nonce.into());
        println!("cipher ");
        let mut data = key_data.ciphertext;
        cipher.apply_keystream(&mut data);
        //let mut data = std::str::from_utf8(&data);

        //    // calculate the HMAC of the resulting cipher, using the hmacKey
        let hmac_key = self.get_hmac_key();
        let mut mac = HmacSha256::new_from_slice(&hmac_key.finalize().into_bytes()).expect("HMAC can take key of any size");
        mac.update(&data);
        //mac.verify_slice(key_data.mac.as_bytes()).unwrap();
        
        let result = mac.finalize();
        let mac = result.into_bytes();
        println!("mac encrypted: {:?}", mac);
        println!("mac encoded: {}", base64::encode(mac));
        

        //     // stripping all the trailing = of the MACs prior comparing
        //     return info['mac'].replaceAll(RegExp(r'=+$'), '') ==
        //         encrypted.mac.replaceAll(RegExp(r'=+$'), '');

        false
    }

    // replace with hkdf
    fn get_aes_key(&self) ->  HmacSha256 {
        let zerosalt: [u8; 32] =  [0; 32];
        // // hash the key with the zeros as secret
        let mut prk = HmacSha256::new_from_slice(&zerosalt).expect("HMAC can take key of any size");
        prk.update(&self.0);
        // var b = Uint8List(1); // generate one byte
        // b[0] = 1; // and set it to one
        let b : [u8; 1] = [1]; 
        // // use the previously resulted MAC as key, and hash the name, with the one-byte added to the end
        // // the result is the aes key
        // final aesKey = Hmac(sha256, prk.bytes).convert(utf8.encode(name) + b);
        let mut aes_key = HmacSha256::new_from_slice(&prk.finalize().into_bytes()).unwrap();
        aes_key.update(&b);
        aes_key
      
    }

    fn get_hmac_key(&self) -> HmacSha256 {
        let zerosalt: [u8; 32] =  [0; 32];
        // // hash the key with the zeros as secret
        let mut prk = HmacSha256::new_from_slice(&zerosalt).expect("HMAC can take key of any size");
        prk.update(&self.0);
        // b[0] = 2; // set the byte to 2 
        let b : [u8; 1] = [2];
        // // use the first computed MAC as a key, this time hashing the aes key plus the name plus the byte two
        // // the result is the HMAC key
        // var hmacKey = Hmac(sha256, prk.bytes).convert(aesKey.bytes + utf8.encode(name) + b);
        let mut hmac_key = HmacSha256::new_from_slice(&prk.finalize().into_bytes()).unwrap();
        let bytes_to_hash = self.get_aes_key().finalize().into_bytes();

        //hmac_key.update([bytes_to_hash, b].concat());
        hmac_key.update(&bytes_to_hash);
        hmac_key
        // // this just returns the raw, derived aes and HMAC keys in an object
        // return _DerivedKeys(aesKey: aesKey.bytes, hmacKey: hmacKey.bytes);
    }
}

#[async_trait(?Send)]
impl Vault for MatrixVault {
    async fn unlock(&self, _password: &str) -> libwallet::Result<Self::Pair> {
        let pair = <Self as CryptoType>::Pair::from_seed(&self.0);
        Ok(pair)
    }
}

