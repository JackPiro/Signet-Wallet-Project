#![allow(unused)]
use std::{collections::{HashMap, HashSet}, path::PathBuf, process::Command};
use std::num::ParseIntError;
use sha2::Sha256;
use hmac::{Hmac, Mac};
use std::convert::TryInto;
use sha2::Sha512;
use secp256k1::{Secp256k1, SecretKey, PublicKey, Message};
use num_bigint::BigUint;
use ripemd::Ripemd160;
use sha2::Digest;
use hex;
use serde_json::Value;

// HMAC alias for HMAC-SHA512.
type HmacSha512 = Hmac<sha2::Sha512>;



pub const WALLET_NAME: &str = "wallet_373";
pub const EXTENDED_PRIVATE_KEY: &str = "tprv8ZgxMBicQKsPfDLVSJEVPjpu7Bhctgf9bsHt8Zf12FrbweZs4BNCT7LFVQr2sNNrANzsfrL2rs9SNxy5ZwQbrc4Jxac9Cq73a4a3UjhPH6Q";

pub const MULTISIG_AMOUNT: u64 = 1_000_000;
// Fee values (sat)
pub const FEE_TX1: u64 = 10_000;
const FEE_TX2: u64 = 5_000;

const OP_RETURN_DATA: &str = "JackPiro";

#[derive(Debug, PartialEq)]
pub struct ExKey {
    version: [u8; 4],
    depth: [u8; 1],
    finger_print: [u8; 4],
    child_number: [u8; 4],
    chaincode: [u8; 32],
    key: [u8; 32],
}

// Wallet Recovery...

/// WalletState now includes a list of UTXOs. Each UTXO is represented as (outpoint, value)
/// where outpoint is a string in the format "txid:vout".
pub struct WalletState {
    pub utxos: Vec<(String, u64)>,
    pub witness_programs: Vec<String>,
    pub public_keys: Vec<String>,
    pub private_keys: Vec<String>,
}

impl WalletState {
    pub fn balance(&self) -> u64 {
        self.utxos.iter().map(|(_, v)| *v).sum()
    }
}

/// Our simplified error type.
#[derive(Debug)]
pub enum BalanceError {
    MissingCodeCantRun,
    RpcError(String),
    Other(String),
}

/// --- Base58Check Decoding and Extended Key Deserialization ---
/// (These functions are largely reused from Week 1.)
#[derive(Debug)]
pub enum Base58Error {
    InvalidCharacter(char),
    ChecksumMismatch,
    Unknown(String),
}

/// Decode a Base58Check string into its raw bytes.
pub fn base58_decode(base58_string: &str) -> Result<Vec<u8>, Base58Error> {
    const BASE58_ALPHABET: &str =
        "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let mut acc = BigUint::default();
    let base = BigUint::from(58u32);
    for ch in base58_string.chars() {
        let digit = BASE58_ALPHABET.find(ch)
            .ok_or(Base58Error::InvalidCharacter(ch))?;
        acc = &acc * &base + BigUint::from(digit as u32);
    }
    let raw = acc.to_bytes_be();
    let expected_total_len = if base58_string.starts_with('x') || base58_string.starts_with('t') {
        82 // extended keys are 78-byte payload + 4-byte checksum
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
    const TPRV: [u8; 4] = [0x04, 0x35, 0x83, 0x94];
    if version != TPRV {
        return Err(DeserializeError::UnknownVersion(version));
    }
    Ok(ExKey {
        version,
        depth,
        finger_print,
        child_number,
        chaincode,
        key,
    })
}

/// Convert a private key to a compressed public key.
pub fn private_key_to_public_key(private_key: &[u8]) -> Vec<u8> {
    let secp = Secp256k1::new();
    let secret_key = SecretKey::from_slice(private_key).unwrap();
    let public_key = PublicKey::from_secret_key(&secp, &secret_key);
    public_key.serialize().to_vec()
}

/// Compute the fingerprint as the first 4 bytes of HASH160(compressed public key).
fn calculate_fingerprint(parent_key: &[u8]) -> [u8; 4] {
    let pubkey = private_key_to_public_key(parent_key);
    let sha = Sha256::digest(&pubkey);
    let hash = Ripemd160::digest(&sha);
    let mut fingerprint = [0u8; 4];
    fingerprint.copy_from_slice(&hash[0..4]);
    fingerprint
}

/// helper: add two 32-byte numbers modulo the secp256k1 order.
fn add_privkeys_mod_n(key: &[u8; 32], tweak: &[u8; 32]) -> Option<[u8; 32]> {
    const CURVE_ORDER: &str = "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141";
    let n = BigUint::parse_bytes(CURVE_ORDER.as_bytes(), 16).unwrap();
    let key_num = BigUint::from_bytes_be(key);
    let tweak_num = BigUint::from_bytes_be(tweak);
    let res = (key_num + tweak_num) % n;
    if res == BigUint::from(0u32) {
        return None;
    }
    let mut bytes = [0u8; 32];
    let res_bytes = res.to_bytes_be();
    bytes[32 - res_bytes.len()..].copy_from_slice(&res_bytes);
    Some(bytes)
}

/// Hardened derivation (CKDpriv) for indices ≥ 0x80000000.
pub fn derive_priv_child(parent: &ExKey, child_index: u32) -> Option<ExKey> {
    if child_index < 0x80000000 {
        unimplemented!("Non-hardened derivation not used here");
    }
    let mut data = Vec::with_capacity(37);
    data.push(0x00);
    data.extend_from_slice(&parent.key);
    data.extend_from_slice(&child_index.to_be_bytes());
    let mut hmac = HmacSha512::new_from_slice(&parent.chaincode).ok()?;
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

/// non-hardened derivation (CKDpriv) for indices < 0x80000000.
fn derive_priv_child_nonhardened(parent: &ExKey, child_index: u32) -> Option<ExKey> {
    if child_index >= 0x80000000 {
        unimplemented!("Use hardened derivation");
    }
    let parent_pubkey = private_key_to_public_key(&parent.key);
    let mut data = Vec::with_capacity(33 + 4);
    data.extend_from_slice(&parent_pubkey);
    data.extend_from_slice(&child_index.to_be_bytes());
    let mut hmac = HmacSha512::new_from_slice(&parent.chaincode).ok()?;
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

/// Parse a derivation path and derive keys sequentially.
fn get_child_key_at_path(mut key: ExKey, derivation_path: &str) -> ExKey {
    let path = if derivation_path.starts_with("m/") {
        &derivation_path[2..]
    } else {
        derivation_path
    };
    for part in path.split('/') {
        if part.is_empty() { continue; }
        let hardened = part.ends_with('h') || part.ends_with('\'');
        let index_str = if hardened { &part[..part.len()-1] } else { part };
        let index: u32 = index_str.parse().expect("Invalid index in path");
        let index = if hardened { index + 0x80000000 } else { index };
        key = if index >= 0x80000000 {
            derive_priv_child(&key, index).expect("Hardened derivation failed")
        } else {
            derive_priv_child_nonhardened(&key, index).expect("Non-hardened derivation failed")
        };
    }
    key
}

/// generate a sequence of non-hardened child keys from a branch key.
fn get_keys_at_child_key_path(branch: ExKey, num_keys: u32) -> Vec<ExKey> {
    let mut keys = Vec::new();
    for i in 0..num_keys {
        let child = derive_priv_child_nonhardened(&branch, i)
            .expect("Non-hardened derivation failed");
        keys.push(child);
    }
    keys
}

/// Generate the p2wpkh witness program from a compressed public key.
fn get_p2wpkh_program(pubkey: &[u8]) -> Vec<u8> {
    let sha = Sha256::digest(pubkey);
    let hash = Ripemd160::digest(&sha);
    let mut program = Vec::with_capacity(22);
    program.push(0x00); // version 0
    program.push(0x14); // push 20 bytes
    program.extend_from_slice(&hash);
    program
}

/// Generate the p2wsh witness program from a redeem script.
/// Witness program: 0x00, 0x20, SHA256(redeem_script)
pub fn get_p2wsh_program(redeem_script: &[u8]) -> Vec<u8> {
    let hash = Sha256::digest(redeem_script);
    let mut program = Vec::with_capacity(34);
    program.push(0x00);
    program.push(0x20);
    program.extend_from_slice(&hash);
    program
}

// scan bloxks...
fn scan_blocks_for_utxos(witness_set: &HashSet<String>) -> Result<HashMap<String, u64>, BalanceError> {
    let mut utxos: HashMap<String, u64> = HashMap::new();
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
                        // Use round() to avoid floating–point issues.
                        let value_sats = (value_btc * 100_000_000f64).round() as u64;
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
                        if let (Some(prev_txid), Some(prev_vout)) = (vin["txid"].as_str(), vin["vout"].as_u64()) {
                            let outpoint = format!("{}:{}", prev_txid, prev_vout);
                            utxos.remove(&outpoint);
                        }
                    }
                }
            }
        }
    }
    Ok(utxos)
}

/// wrapper for bitcoin-cli RPC calls.
fn bcli(cmd: &str) -> Result<Vec<u8>, BalanceError> {
    let mut args = vec!["-signet"];
    args.extend(cmd.split_whitespace());
    let result = Command::new("bitcoin-cli")
        .args(&args)
        .output()
        .map_err(|_| BalanceError::MissingCodeCantRun)?;
    if result.status.success() {
        Ok(result.stdout)
    } else {
        Err(BalanceError::RpcError(String::from_utf8_lossy(&result.stderr).to_string()))
    }
}

/// Recover the wallet state (keys and UTXOs) by:
/// 1. Decoding the extended private key
/// 2. Deriving the branch key from the descriptor "84h/1h/0h/0"
/// 3. Deriving 2000 child keys
/// 4. Computing witness programs for each key
/// 5. Scanning blocks 0–300 for outputs matching those witness programs
pub fn recover_wallet_state(
    extended_private_key: &str,
) -> Result<WalletState, BalanceError> {
    // 1. Decode and deserialize master key.
    let decoded = base58_decode(extended_private_key)
        .map_err(|_| BalanceError::MissingCodeCantRun)?;
    let master = deserialize_key(&decoded)
        .map_err(|_| BalanceError::MissingCodeCantRun)?;
    // 2. Derive branch key.
    let branch = get_child_key_at_path(master, "84h/1h/0h/0");
    // 3. Derive 2000 child keys.
    let child_keys = get_keys_at_child_key_path(branch, 2000);
    let mut private_keys = Vec::new();
    let mut public_keys = Vec::new();
    let mut witness_programs = Vec::new();
    for key in &child_keys {
        private_keys.push(hex::encode(&key.key));
        let pubkey = private_key_to_public_key(&key.key);
        public_keys.push(hex::encode(&pubkey));
        let witness = get_p2wpkh_program(&pubkey);
        witness_programs.push(hex::encode(&witness));
    }
    let witness_set: HashSet<String> = witness_programs.iter().cloned().collect();
    // 5. Scan blockchain for UTXOs.
    let utxos_map = scan_blocks_for_utxos(&witness_set)?;
    let utxos: Vec<(String, u64)> = utxos_map.into_iter().collect();
    for (outpoint, value) in &utxos {
        // println!("Found UTXO: {} with value {}", outpoint, value);
        // println!("Script: {}", witness_programs[0]); // First key's script
    }
    Ok(WalletState {
        utxos,
        public_keys,
        private_keys,
        witness_programs,
    })
}

//transaction sctructures....

/// Transaction input.
#[derive(Debug)]
pub struct TxInput {
    txid: Vec<u8>,         // little-endian bytes
    vout: u32,
    script_sig: Vec<u8>,   // always empty for segwit spending
    sequence: u32,         // 0xffffffff
    pub witness: Vec<Vec<u8>>,
}

/// Transaction output.
#[derive(Debug)]
pub struct TxOutput {
    pub value: u64,            // in satoshis
    pub script_pubkey: Vec<u8>,
}

/// A segwit transaction.
#[derive(Debug)]
pub struct Transaction {
    pub version: u32,
    pub inputs: Vec<TxInput>,
    pub outputs: Vec<TxOutput>,
    pub lock_time: u32,
}

/// Encode a u64 as a CompactSize (varint).
fn encode_varint(n: u64) -> Vec<u8> {
    if n < 0xfd {
        vec![n as u8]
    } else if n <= 0xffff {
        let mut v = vec![0xfd];
        v.extend(&(n as u16).to_le_bytes());
        v
    } else if n <= 0xffff_ffff {
        let mut v = vec![0xfe];
        v.extend(&(n as u32).to_le_bytes());
        v
    } else {
        let mut v = vec![0xff];
        v.extend(&n.to_le_bytes());
        v
    }
}

/// Serialize a transaction input (non-witness part).
fn serialize_txin(input: &TxInput) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend(&input.txid);
    buf.extend(&input.vout.to_le_bytes());
    let script_len = encode_varint(input.script_sig.len() as u64);
    buf.extend(script_len);
    buf.extend(&input.script_sig);
    buf.extend(&input.sequence.to_le_bytes());
    buf
}

/// Serialize a transaction output.
fn serialize_txout(output: &TxOutput) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend(&output.value.to_le_bytes());
    let script_len = encode_varint(output.script_pubkey.len() as u64);
    buf.extend(script_len);
    buf.extend(&output.script_pubkey);
    buf
}

/// Serialize the transaction in segwit format.
pub fn serialize_transaction(tx: &Transaction) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend(&tx.version.to_le_bytes());
    // Marker and flag for segwit.
    buf.push(0x00);
    buf.push(0x01);
    buf.extend(encode_varint(tx.inputs.len() as u64));
    for input in &tx.inputs {
        buf.extend(serialize_txin(input));
    }
    buf.extend(encode_varint(tx.outputs.len() as u64));
    for output in &tx.outputs {
        buf.extend(serialize_txout(output));
    }
    // Witness data.
    for input in &tx.inputs {
        buf.extend(encode_varint(input.witness.len() as u64));
        for wit in &input.witness {
            buf.extend(encode_varint(wit.len() as u64));
            buf.extend(wit);
        }
    }
    buf.extend(&tx.lock_time.to_le_bytes());
    buf
}

/// Serialize transaction without witness data (for txid).
pub fn serialize_transaction_no_witness(tx: &Transaction) -> Vec<u8> {
    let mut buf = Vec::new();
    buf.extend(&tx.version.to_le_bytes());
    buf.extend(encode_varint(tx.inputs.len() as u64));
    for input in &tx.inputs {
        buf.extend(serialize_txin(input));
    }
    buf.extend(encode_varint(tx.outputs.len() as u64));
    for output in &tx.outputs {
        buf.extend(serialize_txout(output));
    }
    buf.extend(&tx.lock_time.to_le_bytes());
    buf
}

/// double SHA256 hash.
pub fn double_sha256(data: &[u8]) -> Vec<u8> {
    let first = Sha256::digest(data);
    let second = Sha256::digest(&first);
    second.to_vec()
}

// BIP 143 Sighash calc

pub fn segwit_sighash(tx: &Transaction, input_index: usize, script_code: &[u8], value: u64) -> [u8; 32] {
    let sighash_type: u32 = 0x01;
    // 1. hashPrevouts: hash of all input outpoints.
    let mut prevouts = Vec::new();
    for inp in &tx.inputs {
        prevouts.extend(&inp.txid);
        prevouts.extend(&inp.vout.to_le_bytes());
    }
    let hash_prevouts = double_sha256(&prevouts);
    // 2. hashSequence: hash of all input sequences.
    let mut sequences = Vec::new();
    for inp in &tx.inputs {
        sequences.extend(&inp.sequence.to_le_bytes());
    }
    let hash_sequence = double_sha256(&sequences);
    // 3. hashOutputs: hash of all outputs.
    let mut outs = Vec::new();
    for out in &tx.outputs {
        outs.extend(&out.value.to_le_bytes());
        let script_len = encode_varint(out.script_pubkey.len() as u64);
        outs.extend(script_len);
        outs.extend(&out.script_pubkey);
    }
    let hash_outputs = double_sha256(&outs);
    // 4. Preimage assembly.
    let mut preimage = Vec::new();
    preimage.extend(&tx.version.to_le_bytes());
    preimage.extend(&hash_prevouts);
    preimage.extend(&hash_sequence);
    // For the input being signed:
    let inp = &tx.inputs[input_index];
    preimage.extend(&inp.txid);
    preimage.extend(&inp.vout.to_le_bytes());
    // scriptCode is prefixed with its CompactSize length.
    let script_len = encode_varint(script_code.len() as u64);
    preimage.extend(script_len);
    preimage.extend(script_code);
    preimage.extend(&value.to_le_bytes());
    preimage.extend(&inp.sequence.to_le_bytes());
    preimage.extend(&hash_outputs);
    preimage.extend(&tx.lock_time.to_le_bytes());
    preimage.extend(&sighash_type.to_le_bytes());
    let sighash = double_sha256(&preimage);
    let mut result = [0u8; 32];
    result.copy_from_slice(&sighash);
    result
}

// ================================= Multisig Redeem Script Construction ====================================

const OP_2: u8 = 0x52;
const OP_CHECKMULTISIG: u8 = 0xae;

/// Create a 2-of-2 multisig redeem script from two compressed public keys.
pub fn create_multisig_redeem_script(pubkey1: &[u8], pubkey2: &[u8]) -> Vec<u8> {
    let mut script = Vec::new();
    // Push number 2 (required signatures)
    script.push(OP_2);
    // Push first public key (length byte + key bytes)
    script.push(pubkey1.len() as u8);
    script.extend_from_slice(pubkey1);
    // Push second public key.
    script.push(pubkey2.len() as u8);
    script.extend_from_slice(pubkey2);
    // Push total public keys count (2)
    script.push(OP_2);
    // Append OP_CHECKMULTISIG.
    script.push(OP_CHECKMULTISIG);
    script
}

// Build transactions

/// Build the first transaction spending from a p2wpkh UTXO to create:
///   - A multisig (p2wsh) output of exactly 0.01 BTC.
///   - A change output returning the remainder (minus fee) to our p2wpkh address.
/// For p2wpkh spending, the scriptCode (for signing) is the standard script built from the public key.

//one with comments:
// pub fn build_spend_tx_from_p2wpkh(
//     utxo_outpoint: &str,
//     utxo_value: u64,
//     multisig_witness_program: &[u8],
//     change_pubkey_hash: &[u8],
// ) -> Transaction {
//     // Define fee and multisig output amount.
//     let fee = FEE_TX1;
//     let multisig_value = MULTISIG_AMOUNT; // 1,000,000 satoshis = 0.01 BTC

//     // Calculate change (UTXO value minus multisig output and fee).
//     let change_value = utxo_value
//         .checked_sub(multisig_value + fee)
//         .expect("Selected UTXO value is insufficient.");
    
//     // Parse the UTXO outpoint ("txid:vout") and decode the txid.
//     let parts: Vec<&str> = utxo_outpoint.split(':').collect();
//     let txid_hex = parts[0];
//     let vout: u32 = parts[1].parse().unwrap();

//     // println!("\n=== Building First Transaction ===");
//     // println!("Input TXID (before reverse): {}", txid_hex);
//     // println!(
//     //     "Input TXID (after reverse): {}",
//     //     hex::encode(&hex::decode(txid_hex)
//     //         .unwrap()
//     //         .iter().rev().cloned().collect::<Vec<_>>())
//     // );
//     // println!("Input value: {}", utxo_value);

//     // Create the input using the reversed txid.
//     let input = TxInput {
//         txid: {
//             let mut txid_bytes = hex::decode(txid_hex).expect("Invalid txid in UTXO");
//             txid_bytes.reverse(); // Convert to little‑endian.
//             txid_bytes
//         },
//         vout,
//         script_sig: vec![], // For segwit, scriptSig is empty.
//         sequence: 0xffffffff,
//         witness: vec![],
//     };

//     // println!("\n=== Multisig Output Details ===");
//     // println!("Using multisig witness program: {}", hex::encode(multisig_witness_program));

//     // Build multisig (p2wsh) output.
//     let multisig_output = TxOutput {
//         value: multisig_value,
//         script_pubkey: multisig_witness_program.to_vec(),
//     };

//     // Build change output (p2wpkh). The standard p2wpkh scriptPubKey is:
//     // 0x00 0x14 {20-byte pubkey hash}.
//     let mut change_script = Vec::with_capacity(22);
//     change_script.push(0x00);
//     change_script.push(0x14);
//     change_script.extend_from_slice(change_pubkey_hash);
//     let change_output = TxOutput {
//         value: change_value,
//         script_pubkey: change_script,
//     };

//     Transaction {
//         version: 2,
//         inputs: vec![input],
//         outputs: vec![multisig_output, change_output],
//         lock_time: 0,
//     }
// }

pub fn build_spend_tx_from_p2wpkh(
    utxo_outpoint: &str,
    utxo_value: u64,
    multisig_witness_program: &[u8],
    change_pubkey_hash: &[u8],
) -> Transaction {
    // Define fee and multisig output amount.
    let fee = FEE_TX1;
    let multisig_value = MULTISIG_AMOUNT; // 1,000,000 satoshis = 0.01 BTC

    // Calculate change (UTXO value minus multisig output and fee).
    let change_value = utxo_value.checked_sub(multisig_value + fee)
        .expect("Selected UTXO value is insufficient.");
    
    // Parse the UTXO outpoint ("txid:vout") and decode the txid.
    let parts: Vec<&str> = utxo_outpoint.split(':').collect();
    let txid_hex = parts[0];
    let vout: u32 = parts[1].parse().unwrap();

        println!("\n=== Building First Transaction ===");
        println!("Input TXID (before reverse): {}", txid_hex);
        println!(
            "Input TXID (after reverse): {}",
            hex::encode(&hex::decode(txid_hex)
                .unwrap()
                .iter().rev().cloned().collect::<Vec<_>>())
        );
        println!("Input value: {}", utxo_value);

    // Create the input using the reversed txid (little‑endian).
    let input = TxInput {
        txid: {
            let mut txid_bytes = hex::decode(txid_hex).expect("Invalid txid in UTXO");
            txid_bytes.reverse();
            txid_bytes
        },
        vout,
        script_sig: vec![], // For segwit, scriptSig is empty.
        sequence: 0xffffffff,
        witness: vec![],
    };

    println!("\n=== Multisig Output Details ===");
    println!("Using multisig witness program: {}", hex::encode(multisig_witness_program));

    // Build multisig (P2WSH) output. The multisig_witness_program should be computed as:
    //   get_p2wsh_program(&create_multisig_redeem_script(&key0_pub, &key1_pub))
    let multisig_output = TxOutput {
        value: multisig_value,
        script_pubkey: multisig_witness_program.to_vec(),
    };

    // Build change output (P2WPKH). The standard P2WPKH scriptPubKey is:
    //   0x00 0x14 {20-byte pubkey hash}.
    let mut change_script = Vec::with_capacity(22);
    change_script.push(0x00);
    change_script.push(0x14);
    change_script.extend_from_slice(change_pubkey_hash);
    let change_output = TxOutput {
        value: change_value,
        script_pubkey: change_script,
    };

    Transaction {
        version: 2,
        inputs: vec![input],
        outputs: vec![multisig_output, change_output],
        lock_time: 0,
    }
}



/// Build the second transaction spending the multisig (p2wsh) output created in tx1.
/// It creates:
///   - An OP_RETURN output with your full name (configurable).
///   - A change output (p2wpkh) back to your key0.
// with comments

// pub fn build_spend_tx_from_multisig(
//     prev_txid: &str,
//     prev_vout: u32,
//     prev_value: u64,
//     redeem_script: &[u8],
//     change_pubkey_hash: &[u8],
// ) -> Transaction {
//     let fee = FEE_TX2;
//     // Calculate change (the multisig UTXO value minus fee).
//     let change_value = prev_value
//         .checked_sub(fee)
//         .expect("Insufficient multisig UTXO value");

//     // Decode and reverse the previous txid so that it is in little‑endian order.
//     let mut prev_txid_bytes = hex::decode(prev_txid).expect("Invalid prev txid");
//     prev_txid_bytes.reverse();

//     // Build the input using the reversed txid.
//     let input = TxInput {
//         txid: prev_txid_bytes, // Use the reversed txid.
//         vout: prev_vout,
//         script_sig: vec![],
//         sequence: 0xffffffff,
//         witness: vec![], // The witness will be added after signing.
//     };

//     // println!("\n=== Building Second Transaction ===");
//     // println!("Input TXID: {}", prev_txid);
//     // println!("Input value: {}", MULTISIG_AMOUNT);

//     // Build an OP_RETURN output that encodes your configurable full name.
//     let op_return_data = OP_RETURN_DATA.as_bytes();
//     let mut op_return_script = Vec::new();
//     op_return_script.push(0x6a); // OP_RETURN opcode.
//     op_return_script.push(op_return_data.len() as u8); // Push length.
//     op_return_script.extend_from_slice(op_return_data);
//     let op_return_output = TxOutput {
//         value: 0,
//         script_pubkey: op_return_script,
//     };

//     // Build the change output (p2wpkh). Its scriptPubKey is:
//     // 0x00 0x14 {20-byte pubkey hash}.
//     let mut change_script = Vec::with_capacity(22);
//     change_script.push(0x00);
//     change_script.push(0x14);
//     change_script.extend_from_slice(change_pubkey_hash);
//     let change_output = TxOutput {
//         value: change_value,
//         script_pubkey: change_script,
//     };

//     Transaction {
//         version: 2,
//         inputs: vec![input],
//         outputs: vec![op_return_output, change_output],
//         lock_time: 0,
//     }
// }

pub fn build_spend_tx_from_multisig(
    prev_txid: &str,
    prev_vout: u32,
    prev_value: u64,
    redeem_script: &[u8],
    change_pubkey_hash: &[u8],
) -> Transaction {
    let fee = FEE_TX2;
    // Calculate change (the multisig UTXO value minus fee).
    let change_value = prev_value
        .checked_sub(fee)
        .expect("Insufficient multisig UTXO value");

    // Decode and reverse the previous txid so that it is in little‑endian order.
    let mut prev_txid_bytes = hex::decode(prev_txid).expect("Invalid prev txid");
    prev_txid_bytes.reverse();

    // Build the input using the reversed txid.
    let input = TxInput {
        txid: prev_txid_bytes, // Use the correctly reversed txid.
        vout: prev_vout,
        script_sig: vec![],
        sequence: 0xffffffff,
        witness: vec![], // The witness will be added after signing.
    };

    println!("\n=== Building Second Transaction ===");
    println!("Input TXID: {}", prev_txid);
    println!("Input value: {}", MULTISIG_AMOUNT);


    // Build an OP_RETURN output that encodes your configurable full name.
    let op_return_data = OP_RETURN_DATA.as_bytes();
    let mut op_return_script = Vec::new();
    op_return_script.push(0x6a); // OP_RETURN opcode.
    op_return_script.push(op_return_data.len() as u8); // Push length.
    op_return_script.extend_from_slice(op_return_data);
    let op_return_output = TxOutput {
        value: 0,
        script_pubkey: op_return_script,
    };

    // Build the change output (P2WPKH). Its scriptPubKey is:
    //   0x00 0x14 {20-byte pubkey hash}.
    let mut change_script = Vec::with_capacity(22);
    change_script.push(0x00);
    change_script.push(0x14);
    change_script.extend_from_slice(change_pubkey_hash);
    let change_output = TxOutput {
        value: change_value,
        script_pubkey: change_script,
    };

    Transaction {
        version: 2,
        inputs: vec![input],
        outputs: vec![op_return_output, change_output],
        lock_time: 0,
    }
}




// ================================= Signing Functions ====================================

/// Sign a segwit p2wpkh input per BIP 143.  
/// For p2wpkh spending, the scriptCode is the standard p2wpkh script (without the length prefix).
pub fn sign_p2wpkh_input(
    tx: &Transaction,
    input_index: usize,
    script_code: &[u8],
    value: u64,
    privkey: &[u8],
) -> Vec<u8> {
    let sighash = segwit_sighash(tx, input_index, script_code, value);
    // println!("Sighash to sign: {}", hex::encode(&sighash));
    
    // After signing:
    let secp = Secp256k1::new();
    let msg = Message::from_slice(&sighash).expect("32-byte hash");
    let secret_key = SecretKey::from_slice(privkey).expect("Valid secret key");
    let sig = secp.sign_ecdsa(&msg, &secret_key);
    let mut der_sig = sig.serialize_der().to_vec();
    der_sig.push(0x01); // append SIGHASH_ALL
    
    // println!("Final signature: {}", hex::encode(&der_sig));
    der_sig
}

/// Sign a multisig input. For multisig spending the scriptCode is the redeem script.
fn sign_multisig_input(
    tx: &Transaction,
    input_index: usize,
    redeem_script: &[u8],
    value: u64,
    privkey: &[u8],
) -> Vec<u8> {
    sign_p2wpkh_input(tx, input_index, redeem_script, value, privkey)
}

/// Given an outpoint string ("txid:vout"), call bitcoin-cli to retrieve the UTXO’s scriptPubKey hex.
/// Returns the hex string (e.g., "00142294344958d61dc5678bb77f65b7778401890874").
pub fn get_utxo_script(outpoint: &str) -> Result<String, BalanceError> {
    // Split the outpoint string into txid and vout.
    let parts: Vec<&str> = outpoint.split(':').collect();
    if parts.len() != 2 {
        return Err(BalanceError::Other("Invalid outpoint format".into()));
    }
    let txid = parts[0];
    let vout: u32 = parts[1].parse().map_err(|_| BalanceError::Other("Invalid vout".into()))?;
    
    // Construct the bitcoin-cli command.
    let cmd = format!("gettxout {} {}", txid, vout);
    
    // Use our existing bcli wrapper to call bitcoin-cli.
    let output_bytes = bcli(&cmd)?;
    let output_str = String::from_utf8(output_bytes)
        .map_err(|_| BalanceError::Other("UTF8 conversion error".into()))?;
    
    // Parse the JSON output.
    let json_val: serde_json::Value = serde_json::from_str(&output_str)
        .map_err(|_| BalanceError::Other("JSON parse error".into()))?;
    
    // Get the "hex" field from scriptPubKey.
    let spk = json_val["scriptPubKey"]["hex"]
        .as_str()
        .ok_or(BalanceError::Other("Missing scriptPubKey hex".into()))?;
    Ok(spk.to_string())
}
