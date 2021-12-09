use matrix_sdk::{ruma::UserId, Client, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::convert::TryFrom;

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


    let key_data = lib::ByteKeyData::new(
            b"IjM4th3Ia84dAoNH8GcvVQ==",
            b"mZZQjRWhK6qv1sLnRbEwT8opxf5d+VWbn/Mk835u8kYlpvSZQRXek0PggIg=",
            b"kqyFK1uzeNWdA1uUju5TLJZaWG4Fhnba04vnZfdcTu8=",
        );
    let valid = matrix_vault.validate_key(&key_data);

    println!("Valid key: {}", valid);
}
