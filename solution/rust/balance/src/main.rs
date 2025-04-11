use balance::{recover_wallet_state, EXTENDED_PRIVATE_KEY, WALLET_NAME};

// fn main() {
//     let wallet_state = recover_wallet_state(EXTENDED_PRIVATE_KEY).unwrap();
//     let balance = wallet_state.balance();

//     println!("{} {:.8}", WALLET_NAME, balance);
// }

// use balance::{base58_decode, deserialize_key};
fn main() {
    // Recover wallet state.
    match recover_wallet_state(EXTENDED_PRIVATE_KEY) {
        Ok(wallet) => {
            let balance_sats = wallet.balance();
            let balance_tbtc = (balance_sats as f64) / 100_000_000f64;
            println!("{} {:.8}", WALLET_NAME, balance_tbtc);
        },
        Err(e) => {
            eprintln!("Error recovering wallet state: {:?}", e);
        }
    }
}