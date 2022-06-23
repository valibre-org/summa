use matrix_sdk::{ruma::UserId, Client, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::convert::TryInto;

use std::env;

mod lib;

/// Gets the user's backup key
///
/// ## Arguments
///
/// `matrix_handle` - User's matrix handle eg. @mat:matrix.org
///
/// `password` - User's matrix password
///
/// ## Examples
/// let key = get_matrix_backup_key("matrix.org", "@user:matrix.org", "password123");
///
pub async fn get_matrix_backup_key(matrix_handle: &str, password: &str) -> Result<String> {
    // Get user access token
    let user = UserId::try_from(matrix_handle)?;
    println!("{:?}", user);
    let client = Client::new_from_user_id(user.clone()).await?;
    let access_token = client
        .login(user.localpart(), password, None, None)
        .await?
        .access_token;

        
    println!("Got Access Token: {}", access_token);
    // client.sync(SyncSettings::default()).await;
    // let sync_token = client.sync_token().await.unwrap();
    // println!("sync token: {}", sync_token);

    // Build right url for Matrix API request
    let request_url = format!(
        "https://matrix.org/_matrix/client/r0/user/{handle}/account_data/m.megolm_backup.v1",
        //"https://matrix.virto.community/_matrix/client/r0/user/{handle}/account_data/m.megolm_backup.v1",
        handle = matrix_handle,
    );

    println!("Formatted URL: {}", request_url.clone());

    // Send request to Matrix API with token
    let client = reqwest::Client::new();
    let res = client
        .get(request_url)
        .bearer_auth(access_token)
        .send()
        .await?
        .json::<HashMap<String, HashMap<String, Value>>>()
        .await?;

    println!("{:?}", res);
    Ok(res["encrypted"].keys().next().unwrap().to_string())
}

#[tokio::main]
async fn main() {
    let args: Vec<String> = env::args().collect();

    //let key = get_matrix_backup_key(&args[1], &args[2]).await;
    //println!("Key: {}", key.unwrap());

    let mut matrix_vault = lib::MatrixVault::new() ;
    matrix_vault.decode_recovery_key(&args[1]);

    let iv : &[u8; 24] = args[2].as_bytes().try_into().expect("arg with incorrect lenght");
    let ciphertext: &[u8; 60] = args[3].as_bytes().try_into().expect("arg with incorrect lenght");
    let mac : &[u8; 44] = args[4].as_bytes().try_into().expect("arg with incorrect lenght");
    let key_data = lib::ByteKeyData::new(iv, ciphertext, mac);
            // b"IOiIR3Q3ENIZ88mHwhnXTg==",
            // b"b14hUivACrWSUSv+MiU6sDCqG8kBecMVubOb0dh6UL4rMdu7ThYn2Df5nzc=",
            // b"FMxAv5oAirfaDdJCl+yKOqVS8inskBbJBPRFglBq//o="
        
    let valid = matrix_vault.validate_key(&key_data);
    //println!("Valid key: {}", valid);
}

