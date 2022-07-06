use aes::cipher::{generic_array::GenericArray, NewCipher, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use matrix_sdk::{ruma::UserId, Client};
use serde::{Deserialize, de::DeserializeOwned, Serialize};
use sha2::Sha256;
use std::convert::TryFrom;
use aes::Aes256Ctr;
use pbkdf2::pbkdf2;
//use rand::{distributions::Alphanumeric, thread_rng, Rng};
use sha2::Sha512;



pub enum MatrixCredentials {
    Passphrase(String),
    Keyfile(String),
}

pub struct MatrixConnector {
    username: String,
    token: String,
    server: String,
}

impl MatrixConnector {
    pub fn new(username: &str, token: &str, server: &str) -> MatrixConnector {
        MatrixConnector {
            username: username.to_string(),
            token: token.to_string(),
            server: server.to_string(),
        }
    }
    //          . conectar, 
    //          . autenticar, 
    pub async fn connect(username: &str, password: &str, server: &str) -> Result<MatrixConnector> {
        let user = UserId::try_from(username).map_err(|_| MatrixError::ConnectionFailed)?;
        let client = Client::new_from_user_id(user.clone()).await.map_err(|_| MatrixError::ConnectionFailed)?;
        let access_token = client
            .login(user.localpart(), password, None, None)
            .await.map_err(|_| MatrixError::ConnectionFailed)?
            .access_token;
        Ok(MatrixConnector { 
            username: username.to_string(), 
            token: access_token.clone(),
            server:  server.to_string(),
        })
    }

    pub async fn get_secret_from_storage(&self, secret_name: &str, credentials: &MatrixCredentials) -> Result<Option<Vec<u8>>> {
        match credentials {
            MatrixCredentials::Keyfile(storage_key) => 
                self.get_secret_using_keyfile(secret_name, storage_key).await.map(|a| Some(a)),
            MatrixCredentials::Passphrase(storage_key) => 
                self.get_secret_using_passphrase(secret_name, storage_key).await.map(|a| Some(a)),
        }
    }

    
    pub async fn save_secret_in_storage(&self, secret_name: &str, secret: &[u8], credentials: &MatrixCredentials) -> Result<()> {
        match credentials {
            MatrixCredentials::Keyfile(storage_key) => 
                self.save_secret_using_keyfile(secret_name, secret, storage_key).await,
            MatrixCredentials::Passphrase(storage_key) => 
                self.save_secret_using_passphrase(secret_name, secret, storage_key).await,
        }
// (7: devolver la seed generada al user para que la pueda guardar si quiere?)
        
    }

    
    async fn get_secret_using_keyfile(&self, secret_name: &str, storage_key: &str) -> Result<Vec<u8>> {
        // decode key
        let mut decoded_key = MatrixKeyOps::decode_recovery_key(storage_key)?;
        // validate key (retrieve key_data)
        decoded_key.key_data = self.get_storage_key_data().await.map(|a| Some(a))?;
        MatrixKeyOps::validate_key(&decoded_key)?;
        
        // get secret 
        let secret = self.get_secret(secret_name, &mut decoded_key).await?;
        // decrypt secret?
        let secret = MatrixKeyOps::decrypt_secret(&secret, &decoded_key)?;

        Ok(secret)
    }

    async fn get_secret_using_passphrase(&self, secret_name: &str, passphrase: &str) -> Result<Vec<u8>> {
        let key_length = 32;
        let passphrase_info = self.get_passphrase_info().await?;
        let mut storage_key = MatrixKeyOps::get_key_from_passphrase(passphrase, &passphrase_info)?;
        storage_key.key_data = self.get_storage_key_data().await.map(|a| Some(a))?;

        // get secret 
        let secret = self.get_secret(secret_name, &mut storage_key).await?;
        // decrypt secret?
        let secret = MatrixKeyOps::decrypt_secret(&secret, &storage_key)?;

        Ok(secret)
    }

    async fn get_passphrase_info(&self) -> Result<PassphraseInfo> {
        let key_data = self.get_storage_key_data().await?;
        key_data.passphrase_info.ok_or(MatrixError::PassphraseInfoMissing)
    }

    // Get secret with given name
    async fn get_secret(&self, secret_name: &str, storage_key: & mut MatrixStorageKey) -> Result<MatrixStorageSecret> {
        let request_url = format!(
            "https://{server}/_matrix/client/v3/user/@{username}/account_data/{secret_name}",
            server = self.server, username = self.username, secret_name = secret_name,
        );
        self.make_get_request::<MatrixStorageSecret>(&request_url).await
    }

    // Get data to validate storage key
    async fn get_storage_key_data(&self) -> Result<KeyData> {
        // get https://{server}/_matrix/client/r0/user/{username}/account_data/m.secret_storage.default_key
        let request_url = format!(
            "https://{server}/_matrix/client/r0/user/@{username}/account_data/m.secret_storage.default_key",
            username = self.username, server = self.server
        );

        #[derive(Deserialize)]
        struct KeyID {
            key: String,
        }
        let key_id = self.make_get_request::<KeyID>(&request_url).await?;

        // get https://{server}/_matrix/client/r0/user/{username}/account_data/m.secret_storage.key.{id_from_previous_request}
        let request_url = format!(
            "https://{server}/_matrix/client/r0/user/@{username}/account_data/m.secret_storage.key.{id_from_previous_request}",
            server = self.server, username = self.username, id_from_previous_request= key_id.key
        );
        self.make_get_request::<KeyData>(&request_url).await
    }

    async fn make_get_request<'a, T>(&self, url: &str) -> Result<T> 
    where T: DeserializeOwned
    {
        let client = reqwest::Client::new();
        let res = client
            .get(url)
            .bearer_auth(&self.token)
            .send()
            .await.map_err(|_| MatrixError::ConnectionFailed)?;
        //response.text?
        //res.json::<T>().await
        let val: T = res.json::<T>().await.unwrap();
        Ok(val)
    }

    async fn decode_and_validate_storage_key(&self, storage_key: &str) -> Result<MatrixStorageKey> {
        // decode key
        let mut decoded_key = MatrixKeyOps::decode_recovery_key(storage_key)?;
        // validate key (retrieve key_data)
        decoded_key.key_data = self.get_storage_key_data().await.map(|a| Some(a))?;
        MatrixKeyOps::validate_key(&decoded_key)?;
        Ok(decoded_key)
    }

    async fn save_secret_using_keyfile(&self, secret_name: &str, secret: &[u8], storage_key: &str) -> Result<()> {
        // decode key
        let mut decoded_key = MatrixKeyOps::decode_recovery_key(storage_key)?;
        // validate key (retrieve key_data)
        decoded_key.key_data = self.get_storage_key_data().await.map(|a| Some(a))?;
        MatrixKeyOps::validate_key(&decoded_key)?;

// 4: generar seed o recibirla del user
// 5: encriptar seed con la llave generada de passphrase/keyfile
        let encrypted = MatrixKeyOps::encrypt_bytes(secret, &MatrixKeyOps::derive_keys(&decoded_key)?, &MatrixKeyOps::create_iv())?;
        let secret = MatrixStorageSecret {encrypted};
// 6: guardar seed y datos para desencriptar la llave 
        self.save_secret(secret_name, &secret).await
    }

    async fn save_secret_using_passphrase(&self, secret_name: &str, secret: &[u8], passphrase: &str) -> Result<()> {
        let key_length = 32;
        let passphrase_info = self.get_passphrase_info().await?;
        let mut storage_key = MatrixKeyOps::get_key_from_passphrase(passphrase, &passphrase_info)?;
        storage_key.key_data = self.get_storage_key_data().await.map(|a| Some(a))?;

        let encrypted = MatrixKeyOps::encrypt_bytes(secret, &MatrixKeyOps::derive_keys(&storage_key)?, &MatrixKeyOps::create_iv())?;
        let secret = MatrixStorageSecret {encrypted};

        self.save_secret(secret_name, &secret).await
    }

    //TODO fix send json part
    async fn save_secret(&self, secret_name: &str, secret: &MatrixStorageSecret) -> Result<()> {
        let request_url = format!(
            "https://{server}/_matrix/client/v3/user/@{username}/account_data/{secret_name}",
            server = self.server, username = self.username, secret_name = secret_name,
        );
        let client = reqwest::Client::new();
        client
            .put(request_url).json(&secret)
            //send secret (json)
            .bearer_auth(&self.token)
            .send()
            .await.map_err(|_| MatrixError::ConnectionFailed)?;
        Ok(())
    }

}



struct MatrixKeyOps {}

impl MatrixKeyOps {
    fn create_iv() -> String {
        todo!()
    }

    fn get_key_from_passphrase(passphrase: &str, passphrase_info: &PassphraseInfo) -> Result<MatrixStorageKey> {
        match passphrase_info.algorithm.as_str() {
            "m.pbkdf2" => Ok(MatrixKeyOps::from_passphrase(passphrase, &passphrase_info.salt, passphrase_info.iterations)),
            _ => Err(MatrixError::PassphraseError)
        }
    }
    /// Retrieve key from passphrase.
    pub fn from_passphrase(passphrase: &str, salt: &str, rounds: u32) -> MatrixStorageKey {
        let mut key = [0u8; 32];

        pbkdf2::<Hmac<Sha512>>(passphrase.as_bytes(), salt.as_bytes(), rounds, &mut key);

        //self.key = Some(key.clone());
        MatrixStorageKey { key, key_data: None}
    }

    // TODO remove println
    /// Decode recovery key from user key
    pub fn decode_recovery_key(recovery_key: &str) -> Result<MatrixStorageKey> {
        // base58 decode
        let mut key = [0u8; 35];
        let decoded_size = bs58::decode(recovery_key.split_whitespace().collect::<String>())
            .into(&mut key).unwrap();
        let mut parity: u8 = 0;
        for i in key {
            parity ^= i;
        }
        if parity != 0 { 
            return Err(MatrixError::InvalidStorageKey);//println!("wrong parity"); 
        }

        // check if we have the correct header prefix
        // OLM_RECOVERY_KEY_PREFIX = [0x8B, 0x01];
        let prefix = [0x8B, 0x01];
        if key[0] != prefix[0] || key[1] != prefix[1] { println!("wrong prefix"); }

        // verify that the length of the key is correct
        if decoded_size - 3 != 32 { println!("wrong length"); }

        
        // strip the prefix and the parity byte to return the raw key
        let slice = &key[2 .. 34]; 
        Ok(MatrixStorageKey{ key: <[u8; 32]>::try_from(slice).unwrap(), key_data: None})
    }

    fn validate_key(storage_key: &MatrixStorageKey) -> Result<()> {
        let keys = Self::derive_keys(storage_key)?;
        //let key_data = storage_key.key_data.as_ref();
        let key_data = storage_key.key_data.as_ref().ok_or(MatrixError::StorageKeyError)?;
        let encrypted = Self::encrypt_bytes(&[0u8; 32], &keys, &key_data.iv.clone())?;
        if encrypted.mac == key_data.mac {
            return Ok(());
        }
        Err(MatrixError::InvalidStorageKey)
    }

    fn derive_keys(storage_key: &MatrixStorageKey) -> Result<Keys> {
        // derive keys
        //aes key
        let zerosalt: [u8; 32] =  [0; 32];
        let mut prk = HmacSha256::new_from_slice(&zerosalt).unwrap();
        prk.update(&storage_key.key);
        let key = prk.finalize().into_bytes();
        let mut result = HmacSha256::new_from_slice(&key).unwrap();
        let b: [u8; 1] = [1];
        result.update(&b);
        let aes_key = result.finalize().into_bytes();
        
        
        //hmac key
        let b: [u8; 1] = [2];
        let mut result = HmacSha256::new_from_slice(&key).unwrap();
        result.update(&aes_key);
        result.update(&b);
        let hmac_key = result.finalize().into_bytes();


        Ok(Keys {
            hmac: hmac_key.into(),
            aes: aes_key.into(),
        })
    }
    
    fn encrypt_bytes(bytes: &[u8], keys: &Keys, iv: &str) -> Result<Encrypted> {
         // encrypt ciphertext with aes-key, iv from key_data and name=""
        let nonce = base64::decode(iv.clone()).unwrap();
        let nonce = GenericArray::from_slice(&nonce);
        let key = GenericArray::from_slice(&keys.aes);
        let mut cipher = Aes256Ctr::new(key.into(), nonce.into());
        let mut data = bytes.to_owned(); 
        cipher.apply_keystream(&mut data);

        // compare mac from encrypt and key_data
        let mut mac = HmacSha256::new_from_slice(&keys.hmac).map_err(|_| MatrixError::StorageKeyError)?;
        mac.update(&data);

        let result = mac.finalize();
        let mac = result.into_bytes();

        Ok(Encrypted {
            iv: iv.to_string(),
            ciphertext: base64::encode(data),
            mac: base64::encode(mac),
        })
    }

    fn encrypt_secret(secret: &MatrixStorageSecret, storage_key: &MatrixStorageKey) -> Result<Vec<u8>> {
        todo!();
    }

    fn decrypt_secret(secret: &MatrixStorageSecret, storage_key: &MatrixStorageKey) -> Result<Vec<u8>> {
        // derive our keys
        let keys = Self::derive_keys(storage_key)?;
        // decode our ciphertext, as it is base64 encoded
        let cipher = base64::decode(&secret.encrypted.ciphertext).map_err(|_| MatrixError::EncryptionError)?;
        // HMAC our cipher with the generated HMAC key, base64'ing it afterwards
        let mut mac = HmacSha256::new_from_slice(&keys.hmac).map_err(|_| MatrixError::EncryptionError)?;
        mac.update(&cipher);
        let hmac = base64::encode(mac.finalize().into_bytes());
        // if macs dont match, error
        if hmac != secret.encrypted.mac { return Err(MatrixError::EncryptionError); }
        //     // compare the resulted MAC with with the one stored, unpadding both encoded values
        //     if (hmac.replaceAll(RegExp(r'=+$'), '') != data.mac.replaceAll(RegExp(r'=+$'), '')) {
        //       throw 'Bad MAC';
        //     }

        let nonce = base64::decode(secret.encrypted.iv.clone()).unwrap();
        let nonce = GenericArray::from_slice(&nonce);
        let key = GenericArray::from_slice(&keys.aes);
        let mut decipher = Aes256Ctr::new(key.into(), nonce.into());
        let mut data = secret.encrypted.ciphertext.as_bytes().to_owned();
        decipher.apply_keystream(&mut data);
        
        
        Ok(data)
    }

}

type HmacSha256 = Hmac<Sha256>;

#[derive(Deserialize, Serialize)]
struct MatrixStorageSecret {
    encrypted: Encrypted,
}

#[derive(Deserialize, Serialize)]
struct Encrypted {
    iv: String,
    ciphertext: String,
    mac: String,
}


struct MatrixStorageKey {
    key: [u8; 32],
    key_data: Option<KeyData>,
}

#[derive(Deserialize)]
struct KeyData {
    algorithm: String,
    iv: String,
    mac: String,
    ciphertext: String,
    key: Option<String>,
    passphrase_info: Option<PassphraseInfo>,
}

#[derive(Deserialize)]
struct PassphraseInfo {
    algorithm: String,
    iterations: u32,
    salt: String,
}

struct Keys {
    hmac: [u8; 32],//String,
    aes: [u8; 32],//String,
}


pub type Result<T> = core::result::Result<T, MatrixError>;

#[derive(Debug)]
#[cfg_attr(feature = "std", derive(thiserror::Error))]
pub enum MatrixError {
    #[cfg_attr(feature = "std", error("Connection to server failed"))]
    ConnectionFailed,
    #[cfg_attr(feature = "std", error("Cannot retrieve passphrase info"))]
    PassphraseInfoMissing,
    #[cfg_attr(feature = "std", error("Error with passphrase"))]
    PassphraseError,
    #[cfg_attr(feature = "std", error("Error with storage key"))]
    StorageKeyError,
    #[cfg_attr(feature = "std", error("Invalid storage key"))]
    InvalidStorageKey,
    #[cfg_attr(feature = "std", error("Error with encryp/decrypt"))]
    EncryptionError,
}



#[cfg(test)]
mod tests { // for MatrixKeyOps
    use crate::matrixconnector::MatrixKeyOps;
    const KEY: [u8; 32] = [177, 233, 182, 25, 203, 212, 180, 46, 125, 20, 100, 5, 52, 173, 164, 18, 7, 123, 103, 28, 125, 0, 90, 80, 171, 42, 204, 85, 83, 143, 72, 204];
    const AES_KEY: [u8; 32] = [36, 210, 94, 26, 31, 61, 150, 36, 254, 74, 165, 26, 71, 248, 25, 61, 13, 192, 116, 71, 100, 63, 154, 14, 3, 194, 206, 233, 65, 179, 74, 234];
    const HMAC_KEY: [u8; 32] = [28, 174, 46, 179, 162, 17, 56, 238, 27, 97, 154, 77, 83, 112, 165, 18, 171, 178, 95, 179, 201, 1, 140, 151, 113, 136, 115, 154, 12, 217, 86, 122];
    const PASSPHRASE: &str = "akJUeiZ2i4P27Uv";
    const KEYFILE: &str = "EsTu q3iZ vRpP LibY Pq7G NJ2v fQdA eWNf W1ng NRkx NfcF XkLe";
    const SALT: &str = "pHUPIs4yOXLHUadIqDOqO0FYrzNx5CFm";
    const IV: &str = "8QZZ8CEZ40oUUawQ845hQw==";
    const HMAC: &str = "YGNxa56Vy48l1NQjwGKMxpZiy+ExyDgRn8xzqCIzGks=";

    #[test]
    /// Retrieve key from passphrase.
    fn key_from_passphrase_test() {
        //let salt = "pHUPIs4yOXLHUadIqDOqO0FYrzNx5CFm";
        let result = MatrixKeyOps::from_passphrase(PASSPHRASE, SALT, 500000);

        assert_eq!(result.key, KEY);
    }

    #[test]
    fn decode_recovery_key_test() {
        let matrix_key = MatrixKeyOps::decode_recovery_key(KEYFILE).unwrap();

        assert_eq!(matrix_key.key, KEY);
    }



    #[test]
    // derive keys test
    fn derive_keys_test() {
        let matrix_key = super::MatrixStorageKey { key: KEY, key_data: None};
        let keys = MatrixKeyOps::derive_keys(&matrix_key).unwrap();
        
        assert_eq!(keys.aes, AES_KEY);
        assert_eq!(keys.hmac, HMAC_KEY);
    }

    #[test]
    // encrypt test
    fn encrypt_bytes_test() {
        let keys = super::Keys { aes: AES_KEY, hmac: HMAC_KEY };
        let encrypted = MatrixKeyOps::encrypt_bytes(&[0u8; 32], &keys, &IV).expect("Error in test encrypting bytes.");

        assert_eq!(encrypted.mac, HMAC);
    }

    #[test]
    // decrypt test
    fn decrypt_secret_test() {
        let secret = super::MatrixStorageSecret{ 
            encrypted: super::Encrypted { iv: IV.to_string(), ciphertext: "+rov/SarxArWx3KB2B1xIe9zOIzrLkEwi6cawkr7CIA=".to_string(), mac: "YGNxa56Vy48l1NQjwGKMxpZiy+ExyDgRn8xzqCIzGks=".to_string() }};
        let matrix_key = super::MatrixStorageKey{key: KEY, key_data: None};
        let decrypted = MatrixKeyOps::decrypt_secret(&secret, &matrix_key).expect("Error decrypting secret test");

        assert_eq!(decrypted, [0u8; 32].to_vec());
    }
}