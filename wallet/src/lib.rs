use matrix_sdk::{ruma::UserId, Client, Result, SyncSettings};
use std::convert::TryFrom;
use std::collections::HashMap;

pub async fn get_user_access_token(email: &str, password: &str) -> Result<String> {
    let user = UserId::try_from(email)?;
    let client = Client::new_from_user_id(user.clone()).await?;

    // First we need to log in.
    let res = client.login(user.localpart(), password, None, None).await?;

    // Syncing is important to synchronize the client state with the server.
    // This method will never return.
    client.sync(SyncSettings::default()).await;
    Ok(res.access_token)
}

