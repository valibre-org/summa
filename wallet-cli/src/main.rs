use wallet::{MatrixVault, Pair, Wallet};

#[async_std::main]
async fn main() {
    let mut wallet: Wallet<_> = MatrixVault::new().into();
    wallet.unlock("").await.unwrap();

    println!("{}", wallet.root_account().unwrap().public());
}
