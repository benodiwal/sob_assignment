use std::{fs::{self, File}, io::Write};
use serde::{Deserialize, Serialize};
use sha1::Digest;
use sha2::Sha256;
use crate::{operations::hash256, scripts::{is_p2pkh_lock, is_p2wpkh_lock, p2pkhlock, verify_p2pkh_script}, utils::{big_to_buf_le, calculate_witness_commitment, encode_varint, generate_merkel_root, hex_string_to_bytes, is_byte_array}};

static mut files : Vec<String> = Vec::new();

#[derive(Debug, Serialize, Deserialize)]
pub struct Transaction {
    version: u64,
    locktime: u64,
    vin: Vec<Vin>,
    vout: Vec<Vout>,
}

#[derive(Debug, Serialize, Deserialize)]
struct Vin {
    txid: String,
    vout: u64,
    prevout: PrevOut,
    scriptsig: String,
    scriptsig_asm: String,
    #[serde(default)]
    witness: Vec<String>,
    is_coinbase: bool,
    sequence: u32,
}

#[derive(Debug, Serialize, Deserialize)]
struct Vout {
    scriptpubkey: String,
    scriptpubkey_asm: String,
    scriptpubkey_type: String,
    #[serde(default)]
    scriptpubkey_address: String,
    value: i64,
}

#[derive(Debug, Serialize, Deserialize)]
struct PrevOut {
    scriptpubkey: String,
    scriptpubkey_asm: String,
    scriptpubkey_type: String,
    scriptpubkey_address: String,
    value: i64,
}

#[allow(unused)]
trait SerializeHexVout {
    fn serialize_hex(&self) -> Vec<u8>;
}

#[allow(unused)]
trait SerializeHexVin {
    fn serialize_hex(&self, scriptpubkey: &mut Vec<u8>) -> Vec<u8>;
}

impl SerializeHexVin for Vin {
    fn serialize_hex(&self, scriptpubkey: &mut Vec<u8>) -> Vec<u8> {
        let mut vout = big_to_buf_le(self.vout, Some(4));
        let mut sequence = big_to_buf_le(self.sequence as u64, Some(4));
        let mut txid = hex_string_to_bytes(&self.txid).unwrap();
        let mut scriptpubkeylen = encode_varint(scriptpubkey.len() as u64);

        txid.reverse();
        txid.append(&mut vout);
        txid.append(&mut scriptpubkeylen);
        txid.append(scriptpubkey);
        txid.append(&mut sequence);

        txid
    }
}

impl SerializeHexVout for Vout {
    fn serialize_hex(&self) -> Vec<u8> {
        let mut value = big_to_buf_le(self.value as u64, Some(8));
        if let Some(mut script_pub_key) = hex_string_to_bytes(&self.scriptpubkey) {
            let mut scriptpubkeylen = encode_varint(script_pub_key.len() as u64);
            value.append(&mut scriptpubkeylen);
            value.append(&mut script_pub_key);
        }
        value
    }
}

pub fn load_transactions_from_mempool(dir_name: &str) -> Result<Vec<Transaction>, Box<dyn std::error::Error>> {
    let mut transactions: Vec<Transaction> = Vec::new();

    let dir = fs::read_dir(dir_name)?;
    for file in dir {
        let entry = file?;
        let path = entry.path();

        let file = path.file_name().unwrap().to_str().unwrap().strip_suffix(".json").unwrap();
        
        unsafe {
            files.push(file.to_string());
        }

        if let Some(ext) = path.extension() {
            if ext == "json" {
                let content = fs::read_to_string(path)?;
                let transaction: Transaction = serde_json::from_str(&content)?;
                transactions.push(transaction);
            }
        }
    }

    // println!("{:?}", transactions[7]);
    Ok(transactions)
}

// pub fn count_number_of_p2pkh_transactions(transactions: Vec<Transaction>) -> i32 {
//     let mut count = 0;

//     for transaction in transactions.iter() {
//         let vin = &transaction.vin;
//         let mut is_true = true;
//         for vin_content in vin {
//             if vin_content.prevout.scriptpubkey_type != "p2pkh" {
//                 is_true = false;
//                 break;
//             }
//         }
//         if is_true {
//             count += 1;
//         }
//     }

//     count
// }

fn is_p2pkh_transaction(transaction: &Transaction) -> bool {
    let vin = &transaction.vin;
        for vin_content in vin {
            if vin_content.prevout.scriptpubkey_type != "p2pkh" {
                return false;
            }
        }
    true
}

fn is_p2wpkh_transaction(transaction: &Transaction) -> bool {
    let vin = &transaction.vin;
        for vin_content in vin {
            if vin_content.prevout.scriptpubkey_type != "v0_p2wpkh" {
                return false;
            }
        }
    true
}

// pub fn count_number_of_p2wpkh_transactions(transactions: Vec<Transaction>) -> i32 {
//      let mut count = 0;

//      for transaction in transactions.iter() {
//          let vin = &transaction.vin;
//          let mut is_true = true;
//          for vin_content in vin {
//              if vin_content.prevout.scriptpubkey_type != "v0_p2wpkh" {
//                  is_true = false;
//                  break;
//             }
//          }
//          if is_true {
//              count += 1;
//          }
//      }

//      count
// }

#[allow(unused)]
#[allow(warnings)]
pub fn verify_p2pkh_transactions(transactions: Vec<Transaction>, file: &mut File) -> String {

    let mut tx_ids_hash: Vec<String> = Vec::new();

    for transaction in transactions.iter() {

        if is_p2pkh_transaction(transaction) {

            let vin = &transaction.vin;
            let vout = &transaction.vout;
            
            // region :--  To calculate fees
            let mut input_sum: i64 = 0;
            let mut output_sum: i64 = 0;

            for vin_content in vin {
                input_sum += vin_content.prevout.value;
            }

            for vout_content in vout {
                output_sum += vout_content.value;            
            }
           
            // endregion :--  To calculate fees

            let mut i = 0;
            let mut is_valid: bool = true;

            for vin_content in vin {
                let mut scriptsig_asm = &vin_content.scriptsig_asm;
                let mut scriptpubkey_asm = &vin_content.prevout.scriptpubkey_asm;

                let scriptsig_asm_array: Vec<&str> = scriptsig_asm.split_whitespace().collect();
                let scriptpubkey_asm_array: Vec<&str> = scriptpubkey_asm.split_whitespace().collect();

                let script = combined_script(scriptsig_asm_array, scriptpubkey_asm_array);
                let sig_hash = transaction.sig_hash_legacy(i);

                if !verify_p2pkh_script(script, sig_hash) {
                    is_valid = false;
                    break;
                }

                i+=1;
            }

            // if !is_valid {
            //     let mut tx_rev = transaction.get_tx_id();
            //     tx_rev.reverse();
            //     println!("{}", hex::encode(tx_rev));
            // }

            if fees_check(input_sum, output_sum) && is_valid {

                let mut tx_rev = transaction.get_tx_id();
                tx_rev.reverse();

                let file_hash = Sha256::digest(tx_rev.clone());
                // if hex::encode(file_hash) == "4c79436e7160b767cc0358e1bb93d52b9ba0844c292cbe97624fc122e1ecf969" {
                //     println!("{:?}", transaction);
                //     break;
                // }

                unsafe {
                    if files.contains(&hex::encode(file_hash)) {
                        tx_ids_hash.push(hex::encode(tx_rev));
                    }
                }

                // println!("{}", hex::encode(file_hash));
            }

        }
    }

    let mut wtx_ids_hash: Vec<String> = tx_ids_hash.clone();
    wtx_ids_hash.insert(0, "0000000000000000000000000000000000000000000000000000000000000000".to_string());
    let witness_commitment = calculate_witness_commitment(wtx_ids_hash);

    let coinbase_tx = Transaction::create_coinbase_transaction(&witness_commitment);
    let mut coinbase_tx_id = hash256(&hex::decode(&coinbase_tx).unwrap());
    coinbase_tx_id.reverse();
    tx_ids_hash.insert(0, hex::encode(coinbase_tx_id));

    file.write_all((coinbase_tx + "\n").as_bytes());  
  
    for tx in &tx_ids_hash {
        file.write_all((tx.clone() + "\n").as_bytes());
    }

    generate_merkel_root(tx_ids_hash.iter().map(|s| s.as_str()).collect()).unwrap()

 }


fn fees_check(input_sum: i64, output_sum: i64) -> bool {
    input_sum-output_sum > 0
}

fn combined_script<'a>(scriptsig_asm_array: Vec<&'a str>, scriptpubkey_asm_array: Vec<&'a str>) -> Vec<&'a str> {
    let mut combined_array: Vec<&str> = Vec::new();
    combined_array.extend(scriptsig_asm_array.iter());
    combined_array.extend(scriptpubkey_asm_array.iter());

    combined_array
}

impl Transaction {

    pub fn verify_input(&self, idx: usize) -> bool {
        let vin = &self.vin[idx];
        let scriptpubkey_asm_array: Vec<&str> = vin.prevout.scriptpubkey_asm.split_whitespace().collect();

        let mut z: Vec<u8> = Vec::new();
        let mut witness: Option<Vec<String>> = Some(Vec::new());

        if is_p2pkh_lock(scriptpubkey_asm_array.clone()) {
            z = self.sig_hash_legacy(idx); 
            witness = None;
        } else if is_p2wpkh_lock(scriptpubkey_asm_array.clone()) {
            z = self.sig_hash_segwit(idx, None);
            witness = Some(vin.witness.clone());
        } else {
            return false;
        }

        let scriptsig_asm = vin.scriptsig_asm.split_whitespace().collect();
        let mut combined = combined_script(scriptsig_asm, scriptpubkey_asm_array);

        true
    }

    #[allow(warnings)]
    pub fn sig_hash_legacy(&self, input: usize) -> Vec<u8> {
        let mut tx_ins: Vec<&Vin> = Vec::new();
        let mut tx_outs: Vec<&Vout> = Vec::new();

        for vin in &self.vin {
            tx_ins.push(vin);
        }

        let mut tx_ins_len = encode_varint(tx_ins.len() as u64);
        let mut tx_ins_hex: Vec<u8> = Vec::new();

        let mut i = 0;
        for tx_in in tx_ins {
            let mut scriptpubkey_str = "";

            if i == input {
                scriptpubkey_str = &tx_in.prevout.scriptpubkey;
            } 

            if let Ok(mut scriptpubkey) = hex::decode(&scriptpubkey_str) {
                tx_ins_hex.append(&mut tx_in.serialize_hex(&mut scriptpubkey));
            }

            i+=1;
        }

        for vout in &self.vout {
            tx_outs.push(vout);
        }

        let mut tx_outs_len = encode_varint(tx_outs.len() as u64);
        let mut tx_outs_hex: Vec<u8> = Vec::new();
        for tx_out in tx_outs {
            tx_outs_hex.append(&mut Vout::serialize_hex(tx_out));
        }

        let mut version = big_to_buf_le(self.version as u64, Some(4));
        let mut lock_time = big_to_buf_le(self.locktime as u64, Some(4));
        let mut sig_hash_type = big_to_buf_le(1u64, Some(4));

        let mut msg_hash_buf: Vec<u8> = Vec::new();

        msg_hash_buf.append(&mut version);
        msg_hash_buf.append(&mut tx_ins_len);
        msg_hash_buf.append(&mut tx_ins_hex);
        msg_hash_buf.append(&mut tx_outs_len);
        msg_hash_buf.append(&mut tx_outs_hex);
        msg_hash_buf.append(&mut lock_time);
        msg_hash_buf.append(&mut sig_hash_type);

        hash256(&msg_hash_buf)

    }

    pub fn sig_hash_segwit(&self, input: usize, witness_script: Option<Vec<String>>) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        
        let vin = &self.vin[input];
        let mut version = big_to_buf_le(self.version, Some(4));

        // Todo
        let mut hash_prevouts: Vec<u8> = self.hash_prevouts();
        let mut hash_sequence: Vec<u8> = self.hash_sequence();

        let mut prev_out = hex::decode(&vin.txid).unwrap();
        prev_out.reverse();

        let mut prev_index = big_to_buf_le(vin.vout, Some(4));

        let mut script_code: Vec<u8> = Vec::new();

        if let Some(witness_script) = witness_script {
            for item in &witness_script {
                script_code.append(&mut encode_varint(witness_script.len() as u64));
                script_code.append(&mut hex::decode(item).unwrap());
            }
        } else {
            let prev_script_pub_key: Vec<&str> = vin.prevout.scriptpubkey.split_whitespace().collect();
            let pkh160 = hex::decode(prev_script_pub_key[1]).unwrap();
            script_code = p2pkhlock(pkh160.as_ref());
        }

        let mut value = big_to_buf_le(vin.prevout.value as u64, Some(4));
        let mut sequence = big_to_buf_le(vin.sequence as u64, Some(4));
        let mut hash_outputs: Vec<u8> = self.hash_outputs();
        let mut locktime = big_to_buf_le(self.locktime, Some(4));
        let mut sig_hash_type = big_to_buf_le(1u64, Some(4));

        buf.append(&mut version);
        buf.append(&mut hash_prevouts);
        buf.append(&mut hash_sequence);
        buf.append(&mut prev_out);
        buf.append(&mut prev_index);
        buf.append(&mut script_code);
        buf.append(&mut value);
        buf.append(&mut sequence);
        buf.append(&mut hash_outputs);
        buf.append(&mut locktime);
        buf.append(&mut sig_hash_type);

        hash256(&buf)
    }

    pub fn serialize_legacy(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.append(&mut big_to_buf_le(self.version, Some(4)));
        buf.append(&mut encode_varint(self.vin.len() as u64));

        let mut serialized_ins: Vec<u8> = Vec::new();
        for vin in &self.vin {
            serialized_ins.append(&mut vin.serialize_hex(&mut hex_string_to_bytes(&vin.scriptsig).unwrap()));
        }

        buf.append(&mut serialized_ins);

        buf.append(&mut encode_varint(self.vout.len() as u64));
        let mut serialized_outs: Vec<u8> = Vec::new();
        for vout in &self.vout {
            serialized_outs.append(&mut vout.serialize_hex());
        }

        buf.append(&mut serialized_outs);
        buf.append(&mut big_to_buf_le(self.locktime, Some(4)));
        
        buf
    }

    pub fn serialize_segwit_tx_id(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.append(&mut big_to_buf_le(self.version, Some(4)));
        buf.append(&mut encode_varint(self.vin.len() as u64));

        let mut serialized_ins: Vec<u8> = Vec::new();
        for vin in &self.vin {
            serialized_ins.append(&mut vin.serialize_hex(&mut hex_string_to_bytes(&vin.scriptsig).unwrap()));
        }

        buf.append(&mut serialized_ins);

        buf.append(&mut encode_varint(self.vout.len() as u64));
        let mut serialized_outs: Vec<u8> = Vec::new();
        for vout in &self.vout {
            serialized_outs.append(&mut vout.serialize_hex());
        }

        buf.append(&mut serialized_outs);
        buf.append(&mut big_to_buf_le(self.locktime, Some(4)));

        buf
    }

    pub fn serialize_segwit(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        buf.append(&mut big_to_buf_le(self.version, Some(4)));

        let buffer: [u8; 2] = [0x00, 0x01];
        buf.append(&mut buffer.to_vec());
        buf.append(&mut encode_varint(self.vin.len() as u64));

        let mut serialized_ins: Vec<u8> = Vec::new();
        for vin in &self.vin {
            serialized_ins.append(&mut vin.serialize_hex(&mut hex_string_to_bytes(&vin.scriptsig).unwrap()));
        }

        buf.append(&mut serialized_ins);

        buf.append(&mut encode_varint(self.vout.len() as u64));
        let mut serialized_outs: Vec<u8> = Vec::new();
        for vout in &self.vout {
            serialized_outs.append(&mut vout.serialize_hex());
        }

        buf.append(&mut serialized_outs);
        buf.append(&mut self.serialize_witness());
        buf.append(&mut big_to_buf_le(self.locktime, Some(4)));
        
        buf
    }

    pub fn serialize_witness(&self) -> Vec<u8> {
        let mut bufs: Vec<Vec<u8>> = Vec::new();
        let mut res: Vec<u8> = Vec::new();

        for vin in &self.vin {
            bufs.push(encode_varint(vin.witness.len() as u64));

            for item in &vin.witness {
                bufs.push(hex::decode(item).unwrap());                   
            }

        }

        for mut buf in bufs {
            res.append(&mut buf);
        }

        res
    }

    pub fn get_tx_id(&self) -> Vec<u8> {
        hash256(&self.serialize_legacy())
    }

    #[allow(unused)]
    pub fn weight(&self) -> usize {
        self.serialize_legacy().len() * 4
    }

    #[allow(unused)]
    pub fn create_coinbase_transaction(witness_commitment: &str) -> String {
        let mut coinbase_tx = String::new();
        coinbase_tx += "01000000";
        coinbase_tx += "00";
        coinbase_tx += "01";
        coinbase_tx += "01";
        coinbase_tx += "0000000000000000000000000000000000000000000000000000000000000000";
        coinbase_tx += "ffffffff";
        coinbase_tx += "2503233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100";
        coinbase_tx += "ffffffff";
        coinbase_tx += "02f595814a000000001976a914edf10a7fac6b32e24daa5305c723f3de58db1bc888ac000000000000000026";
        coinbase_tx += &format!("6a24aa21a9ed{}", witness_commitment);
        coinbase_tx += "0120000000000000000000000000000000000000000000000000000000000000000000000000";
    
        coinbase_tx
    }

    pub fn hash_prevouts(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();
        for vin in &self.vin {
            let mut prev_tx = hex::decode(&vin.txid).unwrap();
            prev_tx.reverse();
            buf.append(&mut prev_tx);
            buf.append(&mut big_to_buf_le(vin.vout, Some(4)));
        }
        hash256(&buf)
    }

    pub fn hash_outputs(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        for vout in &self.vout {
            buf.append(&mut vout.serialize_hex());
        }

        hash256(&buf)
    }

    pub fn hash_sequence(&self) -> Vec<u8> {
        let mut buf: Vec<u8> = Vec::new();

        for vin in &self.vin {
            buf.append(&mut big_to_buf_le(vin.sequence as u64, Some(4)))
        }

        hash256(&buf)
    }

}