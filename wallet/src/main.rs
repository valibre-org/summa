use matrix_sdk::{ruma::UserId, Client, Result};
use serde_json::Value;
use std::collections::HashMap;
use std::convert::TryFrom;

/// Gets the user's backup key
/// 
/// ## Arguments
/// `matrix_domain` - The matrix domain eg. matrix.org
/// 
/// `matrix_handle` - User's matrix handle eg. @mat:matrix.org
/// 
/// `password` - User's matrix password
/// 
/// ## Examples
/// let key = get_matrix_backup_key("matrix.org", "@user:matrix.org", "password123");
/// 
pub async fn get_matrix_backup_key(
    matrix_domain: &str,
    matrix_handle: &str,
    password: &str,
) -> Result<String> {

    // Get user access token
    let user = UserId::try_from(matrix_handle)?;
    let client = Client::new_from_user_id(user.clone()).await?;
    let access_token = client
        .login(user.localpart(), password, None, None)
        .await?
        .access_token;

    println!("Got Access Token: {}", access_token.clone());

    // Build right url for Matrix API request
    let request_url = format!(
        "https://{domain}/_matrix/client/r0/user/{handle}/account_data/m.megolm_backup.v1",
        domain = matrix_domain,
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

    Ok(res["encrypted"].keys().next().unwrap().to_string())
}

#[tokio::main]
async fn main() {
    let key = get_matrix_backup_key(matrix_domain: &str, matrix_handle: &str, password: &str).await;
    println!("Key: {}", key.unwrap());
}
