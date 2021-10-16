use matrix_sdk::{ruma::UserId, Client, Result};
use reqwest::blocking::Client as WebClient;
use std::collections::HashMap;
use std::convert::TryFrom;
use std::result::Result as Res;

pub async fn get_matrix_backup_key(
    matrix_domain: &str,
    matrix_handle: &str,
    password: &str,
) -> Result<String> {
    let user = UserId::try_from(matrix_handle)?;
    let client = Client::new_from_user_id(user.clone()).await?;

    let access_token = client
        .login(user.localpart(), password, None, None)
        .await?
        .access_token;

    println!("Got Access Token: {}", access_token.clone());

    let request_url = format!(
        "https://{domain}/_matrix/client/r0/user/{userId}/account_data/m.megolm_backup.v1",
        domain = matrix_domain,
        userId = matrix_handle,
    );

    println!("Formatted URL: {}", request_url.clone());

    let client = WebClient::new();
    let res = client
        .get(request_url)
        .bearer_auth(access_token)
        .send()?
        .text()
        .unwrap();

    Ok(res)
}

#[tokio::main]
async fn main() {
    let matrix_handle = "";
    let password = "";

    let key = get_matrix_backup_key("matrix.org", matrix_handle, password).await;
    println!("{:?}", key);
}
