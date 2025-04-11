use secp256k1::{Message, SecretKey, Secp256k1, PublicKey};
use sha2::{Sha256, Digest};
use ripemd::Ripemd160;

use spend::{
    recover_wallet_state,
    EXTENDED_PRIVATE_KEY,
    
    // Key and script utilities
    private_key_to_public_key,
    create_multisig_redeem_script,
    get_p2wsh_program,
    
    // transaction building
    build_spend_tx_from_p2wpkh,
    build_spend_tx_from_multisig,
    
    // transaction signing
    sign_p2wpkh_input,
    segwit_sighash,
    
    serialize_transaction,
    serialize_transaction_no_witness,
    double_sha256,
    
    // Constants
    MULTISIG_AMOUNT,
    FEE_TX1,
};

/// Helper function: Given a wallet state, scan through its UTXOs and try to find one whose
/// locking script (retrieved via get_utxo_script) matches one of the witness programs in the wallet.
/// If a match is found, return a tuple (utxo_outpoint, utxo_value, key_index) where key_index
/// is the index in wallet_state.private_keys (and witness_programs) that produced that locking script.
fn select_utxo_for_key(
    wallet_state: &spend::WalletState,
    required: u64,
) -> Result<(&String, &u64, usize), spend::BalanceError> {
    for (outpoint, value) in &wallet_state.utxos {
        if *value < required {
            continue;
        }
        let spk = spend::get_utxo_script(outpoint)?;
        if let Some(idx) = wallet_state.witness_programs.iter().position(|wp| wp == &spk) {
            return Ok((outpoint, value, idx));
        }
    }
    Err(spend::BalanceError::Other("No UTXO found with sufficient funds AND matching one of our keys".into()))
}

fn main() {
    // Recover wallet state (2000 keys, scanned UTXOs)
    let wallet_state = recover_wallet_state(EXTENDED_PRIVATE_KEY)
        .expect("Failed to recover wallet state");
    
    let required = MULTISIG_AMOUNT + FEE_TX1;
    
    // *** UTXO Selection ***
    let (utxo_outpoint, utxo_value, key_index) =
        select_utxo_for_key(&wallet_state, required).expect("No matching UTXO found");
    
    // Use the selected key (do not default to index 0!)
    let key_priv = hex::decode(&wallet_state.private_keys[key_index])
        .expect("Invalid hex in selected key");
    let key_pub = private_key_to_public_key(&key_priv);
    
    // Print key hash verification.
    let key_sha = Sha256::digest(&key_pub);
    let key_hash160 = Ripemd160::digest(&key_sha);
    let key_script = format!("0014{}", hex::encode(&key_hash160));
    println!("\n=== Key Hash Verification ===");
    println!("Using key at index {}:", key_index);
    println!("Public Key: {}", hex::encode(&key_pub));
    println!("HASH160: {}", hex::encode(&key_hash160));
    println!("Expected P2WPKH script: {}", key_script);
    
    // UTXO debugging.
    println!("\n=== UTXO Verification ===");
    println!("Selected UTXO: {}", utxo_outpoint);
    println!("UTXO Value: {}", utxo_value);
    let utxo_parts: Vec<&str> = utxo_outpoint.split(':').collect();
    let txid = utxo_parts[0];
    let vout: u32 = utxo_parts[1].parse().unwrap();
    println!("To verify UTXO, run: bitcoin-cli -signet gettxout {} {}", txid, vout);
    
    // Build the P2WPKH scriptCode for spending this UTXO.
    let mut p2wpkh_script = Vec::new();
    p2wpkh_script.push(0x76); // OP_DUP
    p2wpkh_script.push(0xa9); // OP_HASH160
    p2wpkh_script.push(0x14); // push 20 bytes
    p2wpkh_script.extend_from_slice(&key_hash160);
    p2wpkh_script.push(0x88); // OP_EQUALVERIFY
    p2wpkh_script.push(0xac); // OP_CHECKSIG
    println!("\nScriptCode for signing (P2WPKH): {}", hex::encode(&p2wpkh_script));
    let script_pubkey = format!("0014{}", hex::encode(&key_hash160));
    println!("ScriptPubKey (from UTXO should match): {}", script_pubkey);
    
    // *** Build Transaction 1: spend P2WPKH → multisig ***
    let tx1 = {
        // Use the selected key (from key_index) as the first key.
        // For the multisig, use the second key (always index 1) as before.
        let key1_priv = hex::decode(&wallet_state.private_keys[1])
            .expect("Invalid hex in key1");
        let key1_pub = private_key_to_public_key(&key1_priv);
        let multisig_redeem_script = create_multisig_redeem_script(&key_pub, &key1_pub);
        
        println!("\n=== Multisig Script Details ===");
        println!("Public Key 0 (from selected key): {}", hex::encode(&key_pub));
        println!("Public Key 1: {}", hex::encode(&key1_pub));
        println!("Full Redeem Script: {}", hex::encode(&multisig_redeem_script));
        println!("Script Hash (for P2WSH): {}", hex::encode(&Sha256::digest(&multisig_redeem_script)));
        
        let multisig_witness_program = get_p2wsh_program(&multisig_redeem_script);
        println!("\n=== Script Hash Verification ===");
        println!("Redeem Script: {}", hex::encode(&multisig_redeem_script));
        println!("SHA256: {}", hex::encode(&Sha256::digest(&multisig_redeem_script)));
        println!("Witness Program: {}", hex::encode(&multisig_witness_program));
        
        let mut tx = build_spend_tx_from_p2wpkh(
            utxo_outpoint,
            *utxo_value,
            &multisig_witness_program,
            &key_hash160, // change output goes back to the same selected key
        );
        // Sign tx1 input using the selected key.
        let sig = sign_p2wpkh_input(&tx, 0, &p2wpkh_script, *utxo_value, &key_priv);
        // For P2WPKH, the witness is [signature, pubkey].
        tx.inputs[0].witness.push(sig);
        tx.inputs[0].witness.push(key_pub.clone());
        tx
    };
    
    // Compute tx1 txid (non-witness serialization).
    let tx1_no_wit = serialize_transaction_no_witness(&tx1);
    // Compute the double SHA256 hash.
    let mut tx1_txid = double_sha256(&tx1_no_wit);
    // *** FIX: Reverse the txid bytes so that the hex string is in the standard display order.
    tx1_txid.reverse();
    let tx1_txid_hex = hex::encode(tx1_txid);
    println!("\n=== TXID Calculation Details ===");
    println!("- Will create TXID: {}", tx1_txid_hex);
    println!("Transaction without witness (hex): {}", hex::encode(&tx1_no_wit));
    println!("Hash before byte reversal: {}", hex::encode(&double_sha256(&tx1_no_wit)));
    println!("Final TXID: {}", tx1_txid_hex);
    
    // *** Build Transaction 2: spend multisig output from tx1 ***
    let tx2 = {
        let key1_priv = hex::decode(&wallet_state.private_keys[1]).expect("Invalid hex in key1");
        let key1_pub = private_key_to_public_key(&key1_priv);
        let multisig_redeem_script = create_multisig_redeem_script(&key_pub, &key1_pub);
        let mut tx = build_spend_tx_from_multisig(
            &tx1_txid_hex,   // Correct txid in display (big-endian) order.
            0,
            MULTISIG_AMOUNT,
            &multisig_redeem_script,
            &key_hash160,    // Change output goes back to the selected key
        );
        println!("\n=== Building Second Transaction ===");
        println!("- Attempting to spend from TXID: {}", tx1_txid_hex);
        println!("- At output index: {}", 0);
        println!("- Expected value: {}", MULTISIG_AMOUNT);
        
        let sighash = segwit_sighash(&tx, 0, &multisig_redeem_script, MULTISIG_AMOUNT);
        println!("\n=== Sighash Calculation Verification ===");
        println!("Final sighash: {}", hex::encode(&sighash));
        let secp = Secp256k1::new();
        let msg = Message::from_slice(&sighash).expect("32-byte hash");
        
        let sig0 = secp.sign_ecdsa(&msg, &SecretKey::from_slice(&key_priv).unwrap());
        let mut der_sig0 = sig0.serialize_der().to_vec();
        der_sig0.push(0x01); // SIGHASH_ALL
        
        let sig1 = secp.sign_ecdsa(&msg, &SecretKey::from_slice(&key1_priv).unwrap());
        let mut der_sig1 = sig1.serialize_der().to_vec();
        der_sig1.push(0x01); // SIGHASH_ALL
        
        println!("Signature 0 verifies against selected pubkey? {}",
            secp.verify_ecdsa(
                &msg,
                &secp256k1::ecdsa::Signature::from_der(&der_sig0[..der_sig0.len()-1]).unwrap(),
                &PublicKey::from_slice(&key_pub).unwrap()
            ).is_ok());
        println!("Signature 1 verifies against key1? {}",
            secp.verify_ecdsa(
                &msg,
                &secp256k1::ecdsa::Signature::from_der(&der_sig1[..der_sig1.len()-1]).unwrap(),
                &PublicKey::from_slice(&key1_pub).unwrap()
            ).is_ok());
        
        // Build the multisig witness.
        tx.inputs[0].witness.clear();
        tx.inputs[0].witness.push(vec![]); // Dummy for CHECKMULTISIG bug.
        tx.inputs[0].witness.push(der_sig0);
        tx.inputs[0].witness.push(der_sig1);
        tx.inputs[0].witness.push(multisig_redeem_script);
        
        println!("\n=== Final Witness Stack Verification ===");
        for (i, item) in tx.inputs[0].witness.iter().enumerate() {
            println!("Item {}: length={}, hex={}", i, item.len(), hex::encode(item));
        }
        tx
    };
    
    let tx1_serialized = serialize_transaction(&tx1);
    let tx2_serialized = serialize_transaction(&tx2);
    let tx1_hex = hex::encode(tx1_serialized);
    let tx2_hex = hex::encode(tx2_serialized);
    
    // Output the two raw transaction hex strings (tx1 and tx2).
    println!("{}", tx1_hex);
    println!("{}", tx2_hex);
}
