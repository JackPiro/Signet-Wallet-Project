#![allow(unused)]
use std::{collections::{HashMap, HashSet}, path::PathBuf, process::Command};
use std::num::ParseIntError;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use std::convert::TryInto;
use sha2::Sha512;
use secp256k1::{Secp256k1, SecretKey, PublicKey};
use num_bigint::BigUint;
use ripemd::Ripemd160;
use sha2::Digest;
use hex;
use serde_json::Value;

// HMAC alias for HMAC-SHA512.
type HmacSha512 = Hmac<sha2::Sha512>;

// Provided by administrator.
pub const WALLET_NAME: &str = "wallet_373";
pub const EXTENDED_PRIVATE_KEY: &str = "tprv8ZgxMBicQKsPfDLVSJEVPjpu7Bhctgf9bsHt8Zf12FrbweZs4BNCT7LFVQr2sNNrANzsfrL2rs9SNxy5ZwQbrc4Jxac9Cq73a4a3UjhPH6Q";

#[derive(Debug)]
pub enum BalanceError {
    MissingCodeCantRun,
    // (Other error variants can be added here.)
}


// Extended Key Structure

#[derive(Debug, PartialEq)]
pub struct ExKey {
    version: [u8; 4],
    depth: [u8; 1],
    finger_print: [u8; 4],
    child_number: [u8; 4],
    chaincode: [u8; 32],
    key: [u8; 32],
}


// Wallet State Structure (for later use)

pub struct WalletState {
    utxos: HashMap<String, u64>,
    witness_programs: Vec<String>,
    public_keys: Vec<String>,
    private_keys: Vec<String>,
}

impl WalletState {
    pub fn balance(&self) -> u64 {
        self.utxos.values().sum()
    }
}


// Base58Check Decoding

#[derive(Debug)]
pub enum Base58Error {
    InvalidCharacter(char),
    ChecksumMismatch,
    Unknown(String),
}

/// Decode a Base58Check string. For extended keys (those starting with "x" or "t"),
/// the full decoded data is 82 bytes (78-byte payload + 4-byte checksum). This function
/// returns the payload only (78 bytes).
pub fn base58_decode(base58_string: &str) -> Result<Vec<u8>, Base58Error> {
    const BASE58_ALPHABET: &str = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    
    let mut acc = BigUint::default();
    let base = BigUint::from(58u32);
    for ch in base58_string.chars() {
        let digit = BASE58_ALPHABET.find(ch)
            .ok_or(Base58Error::InvalidCharacter(ch))?;
        acc = &acc * &base + BigUint::from(digit as u32);
    }
    
    let raw = acc.to_bytes_be();
    
    let expected_total_len = if base58_string.starts_with("x") || base58_string.starts_with("t") {
        82
    } else {
        25
    };
    
    let leading_zeros = base58_string.chars().take_while(|&c| c == '1').count();
    
    let mut full_bytes = vec![0u8; leading_zeros];
    full_bytes.extend_from_slice(&raw);
    
    if full_bytes.len() < expected_total_len {
        let mut padded = vec![0u8; expected_total_len - full_bytes.len()];
        padded.extend_from_slice(&full_bytes);
        full_bytes = padded;
    }
    
    if full_bytes.len() != expected_total_len {
        return Err(Base58Error::Unknown(format!(
            "Decoded length {} does not match expected {}",
            full_bytes.len(),
            expected_total_len
        )));
    }
    
    let (payload, checksum) = full_bytes.split_at(expected_total_len - 4);
    let hash_once = Sha256::digest(payload);
    let hash_twice = Sha256::digest(&hash_once);
    if &hash_twice[0..4] != checksum {
        return Err(Base58Error::ChecksumMismatch);
    }
    
    Ok(payload.to_vec())
}


// Deserialization

#[derive(Debug)]
pub enum DeserializeError {
    InvalidLength(usize),
    UnknownVersion([u8; 4]),
    InvalidPrivatePrefix(u8),
}

/// Deserialize a 78-byte payload into an ExKey.
pub fn deserialize_key(bytes: &[u8]) -> Result<ExKey, DeserializeError> {
    if bytes.len() != 78 {
        return Err(DeserializeError::InvalidLength(bytes.len()));
    }
    
    let mut version = [0u8; 4];
    let mut depth = [0u8; 1];
    let mut finger_print = [0u8; 4];
    let mut child_number = [0u8; 4];
    let mut chaincode = [0u8; 32];
    let mut key = [0u8; 32];
    
    version.copy_from_slice(&bytes[0..4]);
    depth[0] = bytes[4];
    finger_print.copy_from_slice(&bytes[5..9]);
    child_number.copy_from_slice(&bytes[9..13]);
    chaincode.copy_from_slice(&bytes[13..45]);
    
    if bytes[45] != 0x00 {
        return Err(DeserializeError::InvalidPrivatePrefix(bytes[45]));
    }
    key.copy_from_slice(&bytes[46..78]);
    
    const XPRV: [u8; 4] = [0x04, 0x88, 0xAD, 0xE4];
    const TPRV: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
    if version != XPRV && version != TPRV {
        return Err(DeserializeError::UnknownVersion(version));
    }
    
    Ok(ExKey { version, depth, finger_print, child_number, chaincode, key })
}


// Public Key Derivation (for fingerprint calculation)

fn private_key_to_public_key(private_key: &[u8]) -> Vec<u8> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(private_key).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    public_key.serialize().to_vec()
}

/// Compute the fingerprint as the first 4 bytes of HASH160(compressed public key).
fn calculate_fingerprint(parent_key: &[u8]) -> [u8; 4] {
    let parent_pubkey = private_key_to_public_key(parent_key);
    let sha256 = Sha256::digest(&parent_pubkey);
    let hash160 = Ripemd160::digest(&sha256);
    let mut fingerprint = [0u8; 4];
    fingerprint.copy_from_slice(&hash160[0..4]);
    fingerprint
}


// Hardened and Non-hardened Derivation

const CURVE_ORDER: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";

/// Helper: add two 32-byte numbers modulo the curve order.
fn add_privkeys_mod_n(key: &[u8; 32], tweak: &[u8; 32]) -> Option<[u8; 32]> {
    let n = BigUint::parse_bytes(CURVE_ORDER.as_bytes(), 16).unwrap();
    let key_num = BigUint::from_bytes_be(key);
    let tweak_num = BigUint::from_bytes_be(tweak);
    let result = (key_num + tweak_num) % n;
    if result == BigUint::from(0u32) {
        return None;
    }
    let mut result_bytes = [0u8; 32];
    let temp = result.to_bytes_be();
    result_bytes[32 - temp.len()..].copy_from_slice(&temp);
    Some(result_bytes)
}

/// Hardened derivation (CKDpriv) for indices ≥ 0x80000000.
pub fn derive_priv_child(parent: &ExKey, child_index: u32) -> Option<ExKey> {
    if child_index < 0x80000000 {
        unimplemented!("Use non-hardened derivation for indices < 0x80000000");
    }
    
    let mut data = Vec::with_capacity(37);
    data.push(0x00);
    data.extend_from_slice(&parent.key);
    data.extend_from_slice(&child_index.to_be_bytes());
    
    println!("\n--- BIP32 CHILD DERIVATION (hardened) ---");
    println!("Parent chaincode: {}", hex::encode(&parent.chaincode));
    println!("Parent key: {}", hex::encode(&parent.key));
    println!("Child index: 0x{:08x}", child_index);
    println!("HMAC input data: {}", hex::encode(&data));
    
    let mut hmac = HmacSha512::new_from_slice(&parent.chaincode)
        .expect("HMAC accepts any key length");
    hmac.update(&data);
    let result = hmac.finalize().into_bytes();
    
    let (il, ir) = result.split_at(32);
    let il_bytes: [u8; 32] = il.try_into().unwrap();
    let ir_bytes: [u8; 32] = ir.try_into().unwrap();
    
    println!("IL: {}", hex::encode(il));
    println!("IR: {}", hex::encode(ir));
    
    let child_key = add_privkeys_mod_n(&parent.key, &il_bytes)?;
    println!("Derived child key: {}", hex::encode(&child_key));
    
    let fingerprint = calculate_fingerprint(&parent.key);
    
    Some(ExKey {
        version: parent.version,
        depth: [parent.depth[0].wrapping_add(1)],
        finger_print: fingerprint,
        child_number: child_index.to_be_bytes(),
        chaincode: ir_bytes,
        key: child_key,
    })
}

/// Non-hardened derivation (CKDpriv) for indices < 0x80000000.
fn derive_priv_child_nonhardened(parent: &ExKey, child_index: u32) -> Option<ExKey> {
    if child_index >= 0x80000000 {
        unimplemented!("For hardened indices use derive_priv_child");
    }
    
    let parent_pubkey = private_key_to_public_key(&parent.key);
    let mut data = Vec::with_capacity(33 + 4);
    data.extend_from_slice(&parent_pubkey);
    data.extend_from_slice(&child_index.to_be_bytes());
    
    println!("\n--- BIP32 CHILD DERIVATION (non-hardened) ---");
    println!("Parent chaincode: {}", hex::encode(&parent.chaincode));
    println!("Parent pubkey: {}", hex::encode(&parent_pubkey));
    println!("Child index: 0x{:08x}", child_index);
    println!("HMAC input data: {}", hex::encode(&data));
    
    let mut hmac = HmacSha512::new_from_slice(&parent.chaincode).unwrap();
    hmac.update(&data);
    let result = hmac.finalize().into_bytes();
    
    let (il, ir) = result.split_at(32);
    let il_bytes: [u8; 32] = il.try_into().unwrap();
    let ir_bytes: [u8; 32] = ir.try_into().unwrap();
    
    let child_key = add_privkeys_mod_n(&parent.key, &il_bytes)?;
    let fingerprint = calculate_fingerprint(&parent.key);
    
    Some(ExKey {
        version: parent.version,
        depth: [parent.depth[0].wrapping_add(1)],
        finger_print: fingerprint,
        child_number: child_index.to_be_bytes(),
        chaincode: ir_bytes,
        key: child_key,
    })
}


// Derivation Path Parsing and Sequential Derivation

fn get_child_key_at_path(mut key: ExKey, derivation_path: &str) -> ExKey {
    // Strip "m/" prefix if present.
    let path = if derivation_path.starts_with("m/") {
        &derivation_path[2..]
    } else {
        derivation_path
    };
    
    for part in path.split('/') {
        if part.is_empty() {
            continue;
        }
        let hardened = part.ends_with('h') || part.ends_with('\'');
        let index_str = if hardened { &part[..part.len()-1] } else { part };
        let index: u32 = index_str.parse().expect("Invalid index in derivation path");
        let index = if hardened { index + 0x80000000 } else { index };
        
        key = if index >= 0x80000000 {
            derive_priv_child(&key, index).expect("Hardened derivation failed")
        } else {
            derive_priv_child_nonhardened(&key, index).expect("Non-hardened derivation failed")
        };
    }
    key
}


// Generate a Sequence of Child Keys from a Branch Key

fn get_keys_at_child_key_path(branch: ExKey, num_keys: u32) -> Vec<ExKey> {
    let mut keys = Vec::new();
    for i in 0..num_keys {
        let child = derive_priv_child_nonhardened(&branch, i)
            .expect("Non-hardened derivation failed");
        keys.push(child);
    }
    keys
}


// Witness Program Generation for p2wpkh

fn get_p2wpkh_program(pubkey: &[u8]) -> Vec<u8> {
    let hash = {
        let sha = Sha256::digest(pubkey);
        Ripemd160::digest(&sha)
    };
    let mut program = Vec::with_capacity(1 + 1 + hash.len());
    program.push(0x00); // SegWit version 0.
    program.push(0x14); // OP_PUSH20 (20 bytes)
    program.extend_from_slice(&hash);
    program
}


// Blockchain Scanning via RPC

/// This function scans blocks 0 to 300 using bitcoin-cli RPC calls, parses the JSON,
/// and builds a UTXO set by matching transaction outputs whose scriptPubKey (in hex)
/// equals one of your derived witness programs.
/// For simplicity, we assume the block JSON contains:
///   - "tx": an array of transactions,
///   - each transaction has "txid", an array "vout" (with "n", "value", and "scriptPubKey.hex"),
///   - and an array "vin" (with "txid" and "vout") for spent outputs.
/// (In a real implementation you would want to robustly define JSON structures.)
fn scan_blocks_for_utxos(witness_set: &HashSet<String>) -> Result<u64, BalanceError> {
    let mut utxos: HashMap<String, u64> = HashMap::new();
    
    // Change: scan blocks 0 to 299
    for block_num in 0..=300 {
        let bhash_bytes = bcli(&format!("getblockhash {}", block_num))?;
        let bhash = String::from_utf8(bhash_bytes)
            .map_err(|_| BalanceError::MissingCodeCantRun)?;
        let bhash = bhash.trim();
        
        let block_bytes = bcli(&format!("getblock {} 2", bhash))?;
        let block_str = String::from_utf8(block_bytes)
            .map_err(|_| BalanceError::MissingCodeCantRun)?;
        let block_json: Value = serde_json::from_str(&block_str)
            .map_err(|_| BalanceError::MissingCodeCantRun)?;
        
        if let Some(tx_array) = block_json["tx"].as_array() {
            for tx in tx_array {
                let txid = tx["txid"].as_str().unwrap_or("");
                
                // Process outputs.
                if let Some(vouts) = tx["vout"].as_array() {
                    for vout in vouts {
                        let n = vout["n"].as_u64().unwrap_or(0);
                        let value_btc = vout["value"].as_f64().unwrap_or(0.0);
                        // Change: Use round() to convert to satoshis.
                        let value_sats = (value_btc * 100_000_000f64).round() as u64;
                        // Change: Convert script hex to lowercase for matching.
                        let script_hex = vout["scriptPubKey"]["hex"].as_str().unwrap_or("").to_lowercase();
                        
                        if witness_set.contains(&script_hex) {
                            let outpoint = format!("{}:{}", txid, n);
                            utxos.insert(outpoint, value_sats);
                        }
                    }
                }
                
                // Process inputs: remove spent outputs.
                if let Some(vins) = tx["vin"].as_array() {
                    for vin in vins {
                        if let (Some(prev_txid), Some(prev_vout)) =
                            (vin["txid"].as_str(), vin["vout"].as_u64())
                        {
                            let outpoint = format!("{}:{}", prev_txid, prev_vout);
                            utxos.remove(&outpoint);
                        }
                    }
                }
            }
        }
    }
    
    // Sum up the UTXO values.
    let total: u64 = utxos.values().sum();
    Ok(total)
}



// Wallet State Recovery

/// Recover the wallet state by:
///   1. Decoding the extended private key.
///   2. Deriving the branch key using the descriptor path 
///   3. Deriving N child keys from that branch.
///   4. Computing compressed public keys and witness programs.
///   5. Scanning blocks 0–300 for outputs with those witness programs and inputs that spend them.
///   6. Tracking UTXOs and computing the balance.
/// This is a skeleton implementation; you may later refine the JSON parsing and error handling.
pub fn recover_wallet_state(
    extended_private_key: &str,
) -> Result<WalletState, BalanceError> {
    // 1. Decode and deserialize your extended private key.
    let decoded = base58_decode(extended_private_key)
        .map_err(|_| BalanceError::MissingCodeCantRun)?;
    let master = deserialize_key(&decoded)
        .map_err(|_| BalanceError::MissingCodeCantRun)?;
    
    // 2. Derive the branch key from your descriptor path.
    let branch = get_child_key_at_path(master, "84h/1h/0h/0");
    
    // 3. Derive child keys from that branch. (For testing, you might start with a smaller number.)
    let child_keys = get_keys_at_child_key_path(branch, 2000);
    
    // 4. For each child key, compute the compressed public key and p2wpkh witness program.
    let mut private_keys = Vec::new();
    let mut public_keys = Vec::new();
    let mut witness_programs = Vec::new();
    
    for key in child_keys {
        private_keys.push(hex::encode(&key.key));
        let pubkey = private_key_to_public_key(&key.key);
        public_keys.push(hex::encode(&pubkey));
        let witness = get_p2wpkh_program(&pubkey);
        witness_programs.push(hex::encode(&witness));
    }
    
    // For easier lookup, put all witness programs in a HashSet.
    let witness_set: HashSet<String> = witness_programs.iter().cloned().collect();
    
    // 5. Scan blocks 0–300 via RPC and build a UTXO set.
    let utxo_total = scan_blocks_for_utxos(&witness_set)?;
    
    println!("Total UTXO value (satoshis): {}", utxo_total);
    
    // Return a WalletState that contains the keys and witness programs.
    // (UTXO details are stored in a HashMap; here we just store the total balance in the UTXO map.)
    Ok(WalletState {
        utxos: {
            let mut m = HashMap::new();
            m.insert("dummy".to_string(), utxo_total);
            m
        },
        public_keys,
        private_keys,
        witness_programs,
    })
}


// Bitcoin CLI RPC Wrapper

fn bcli(cmd: &str) -> Result<Vec<u8>, BalanceError> {
    let mut args = vec!["-signet"];
    args.extend(cmd.split(' '));
    
    let result = Command::new("bitcoin-cli")
        .args(&args)
        .output()
        .map_err(|_| BalanceError::MissingCodeCantRun)?;
    
    if result.status.success() {
        Ok(result.stdout)
    } else {
        Ok(result.stderr)
    }
}


// Unit Tests for New Steps

#[cfg(test)]
mod extra_tests {
    use super::*;
    
    /// Test that get_child_key_at_path produces the same key as manual derivation for "m/0'".
    #[test]
    fn test_get_child_key_at_path() {
        // Use the official test vector 1 master xprv.
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let payload = base58_decode(xprv).unwrap();
        let master = deserialize_key(&payload).unwrap();
        
        let child_manual = derive_priv_child(&master, 0x80000000).unwrap();
        let child_path = get_child_key_at_path(master, "m/0'");
        assert_eq!(child_manual, child_path, "Derivation via path did not match manual derivation");
    }
    
    /// Test that get_keys_at_child_key_path returns a sequence of non-hardened child keys.
    #[test]
    fn test_get_keys_at_child_key_path() {
        let xprv = "xprv9s21ZrQH143K3QTDL4LXw2F7HEK3wJUD2nW2nRk4stbPy6cq3jPPqjiChkVvvNKmPGJxWUtg6LnF5kejMRNNU3TGtRBeJgk33yuGBxrMPHi";
        let payload = base58_decode(xprv).unwrap();
        let master = deserialize_key(&payload).unwrap();
        // Derive a branch key. Here, for testing, we use m/0' as our branch.
        let branch = derive_priv_child(&master, 0x80000000).unwrap();
        let keys = get_keys_at_child_key_path(branch, 10); // test with 10 keys.
        assert_eq!(keys.len(), 10, "Expected 10 child keys");
        for (i, key) in keys.iter().enumerate() {
            println!("Child {}: {}", i, hex::encode(&key.key));
        }
    }
    
    /// Test witness program generation for p2wpkh.
    #[test]
    fn test_get_p2wpkh_program() {
        let pubkey_hex = "0339a36013301597daef41fbe593a02cc513d0b55527ec2df1050e2e8ff49c85c2";
        let pubkey = hex::decode(pubkey_hex).expect("Invalid hex");
        let program = get_p2wpkh_program(&pubkey);
        assert_eq!(program.len(), 22, "Witness program should be 22 bytes");
        assert_eq!(program[0], 0x00, "Witness version should be 0");
        assert_eq!(program[1], 0x14, "Witness push opcode should be 0x14");
    }
    
    /// (Optional) Test a simple RPC call.
    #[test]
    fn test_bcli_getblockcount() {
        // This test will only pass if bitcoin-cli is running on your system.
        match bcli("getblockcount") {
            Ok(output) => println!("Block count: {}", String::from_utf8_lossy(&output)),
            Err(e) => println!("RPC call failed: {:?}", e),
        }
    }
}
