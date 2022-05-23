use aes::cipher::{generic_array::GenericArray, NewCipher, StreamCipher};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use matrix_sdk::{ruma::UserId, Client, Result};
use sha2::Sha256;
use std::{convert::TryFrom, iter::Map, collections::HashMap};
use aes::Aes256Ctr;

pub struct MatrixConnector {
    username: String,
    token: Option<String>,
}

impl MatrixConnector {
    fn new(username: String) -> MatrixConnector {
        MatrixConnector {
            username,
            token: None,
        }
    }
    //          . conectar, 
    //          . autenticar, 
    pub async fn connect(username: &str, password: &str) -> Result<MatrixConnector> {
        let user = UserId::try_from(username)?;
        let client = Client::new_from_user_id(user.clone()).await?;
        let access_token = client
            .login(user.localpart(), password, None, None)
            .await?
            .access_token;
        Ok(MatrixConnector { 
            username: username.to_string(), 
            token: Some(access_token.clone()) 
        })
    }

    //          . guardar secreto, 
    async fn save_secret(&self, secret_name: &str, secret: &MatrixStorageSecret) -> Result<()> {
        let request_url = format!(
            "https://matrix.virto.community/_matrix/client/v3/user/@{username}:virto.community/account_data/{secret_name}",
            username = self.username, secret_name = secret_name,
        );

        let client = reqwest::Client::new();
        client
            .put(request_url)
            //send secret (json)
            .bearer_auth(self.token.as_ref().unwrap())
            .send()
            .await?;
        Ok(())
    }

    //          . obtener secreto,
    async fn get_secret(&self, secret_name: &str) -> Result<MatrixStorageSecret> {
        let request_url = format!(
            "https://matrix.virto.community/_matrix/client/v3/user/@{username}:virto.community/account_data/{secret_name}",
            username = self.username, secret_name = secret_name,
        );

        let client = reqwest::Client::new();
        let res = client
            .get(request_url)
            .bearer_auth(self.token.as_ref().unwrap())
            .send()
            .await?;
        MatrixStorageSecret::from_json(&res.text().await.unwrap())
    } 

    //          . obtener datos para validar key del storage
    async fn get_storage_key_data(&self) -> Result<()> {
        todo!();
    }
}



struct MatrixStorageSecret {}

impl MatrixStorageSecret {
    pub fn from_json(json: &str) -> Result<Self> {
        todo!()
    }
}


struct MatrixKeyOps {
    key: Option<[u8; 32]>,
    key_data: Option<KeyData>,
}

impl MatrixKeyOps {
    fn decode_recovery_key(& mut self,recovery_key: &str) -> Result<Vec<u8>> {
        // base58 decode
        let mut key = [0u8; 35];
        let decoded_size = bs58::decode(recovery_key.split_whitespace().collect::<String>())
            .into(&mut key).unwrap();
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
        if decoded_size - 3 != 32 { println!("wrong length"); }

        
        // strip the prefix and the parity byte to return the raw key
        let slice = &key[2 .. 34];
        self.key = Some(*<&[u8; 32]>::try_from(slice).unwrap());
        let slice = &key[2 .. 34]; 
        Ok(<[u8; 32]>::try_from(slice).unwrap().to_vec())
    }
    fn validate_key(&self) -> bool {
        let keys = self.derive_keys();
        let key_data = self.key_data.as_ref().unwrap();
        let encrypted = self.encrypt_bytes(&[0u8; 32], &keys, &key_data.iv.clone());
        encrypted.mac == key_data.mac
    }
    fn derive_keys(&self) -> Keys {
         // derive keys
        //aes key
        let zerosalt: [u8; 32] =  [0; 32];
        let hk = Hkdf::<Sha256>::new(Some(&zerosalt), self.key.unwrap().as_ref());
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

        Keys {
            hmac: hmac_key.clone(),
            aes: aes_key.clone(),
        }
    }
    
    fn encrypt_bytes(&self, bytes: &[u8], keys: &Keys, iv: &str) -> Encrypted {
        // encrypt ciphertext with aes-key, iv from key_data and name=""
        let nonce = base64::decode(iv.clone()).unwrap();
        let nonce = GenericArray::from_slice(&nonce);
        let key = GenericArray::from_slice(&keys.aes);
        let mut cipher = Aes256Ctr::new(key.into(), nonce.into());
        let mut data = bytes.to_owned(); // to check if the key in self.0 is correct, we need to encrypt a zerosalt and then check the mac
        cipher.apply_keystream(&mut data);
        println!("key: {:?}", data);

        // compare mac from encrypt and key_data
        let mut mac = HmacSha256::new_from_slice(&keys.hmac).expect("HMAC can take key of any size");
        mac.update(&data);

        let result = mac.finalize();
        let mac = result.into_bytes();
        println!("mac encrypted: {:?}", mac);
        println!("mac encoded: {}", base64::encode(mac));
        Encrypted {
            ciphertext: base64::encode(data),
            mac: base64::encode(mac),
        }
    }
    
}
type HmacSha256 = Hmac<Sha256>;

struct Encrypted {
    ciphertext: String,
    mac: String,
}

struct KeyData {
    iv: String,
    ciphertext: String,
    mac: String,
    key: Option<String>,
}

struct Keys {
    hmac: [u8; 32],//String,
    aes: [u8; 32],//String,
}