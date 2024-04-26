use std::fs::OpenOptions;
use std::io::{Read, Seek, Write};
use std::io;
use sha2::{Sha256, Digest};

pub fn big_to_buf_le(mut num: u64, len: Option<usize>) -> Vec<u8> {
    let mut buf = Vec::new();
    while num > 0 {
        buf.push((num & 0xFF) as u8);
        num >>= 8;
    }
    if let Some(len) = len {
        while buf.len() < len {
            buf.push(0);
        }
    }
    buf
}

pub fn encode_varint(mut num: u64) -> Vec<u8> {
    let mut buf = vec![];
    loop {
        let mut byte = (num & 0x7F) as u8;
        num >>= 7;
        if num != 0 {
            byte |= 0x80;
        }
        buf.push(byte);
        if num == 0 {
            break;
        }
    }
    buf
}

pub fn hex_string_to_bytes(hex_string: &str) -> Option<Vec<u8>> {
    if hex_string.len() % 2 != 0 {
        return None;
    }

    let mut bytes = Vec::new();
    for i in (0..hex_string.len()).step_by(2) {
        let byte = match u8::from_str_radix(&hex_string[i..i + 2], 16) {
            Ok(b) => b,
            Err(_) => return None,
        };
        bytes.push(byte);
    }

    Some(bytes)
}

#[allow(unused)]
pub fn generate_merkel_root(mut tx_ids: Vec<&str>) -> Option<String> {
    if tx_ids.is_empty() {
        return None;
    }

    let mut level: Vec<String> = tx_ids.iter().map(|tx_id| {
        let mut tx_id_buf = hex::decode(tx_id).unwrap();
        tx_id_buf.reverse();
        hex::encode(tx_id_buf)
    }).collect();

    while level.len() > 1 {
        let mut next_level: Vec<String> = Vec::new();
        for i in (0..level.len()).step_by(2) {
            let pair_hash = if i + 1 == level.len() {
                hash_25(&hex::decode(&(level[i].clone() + &level[i])).unwrap())
            } else {
                hash_25(&hex::decode(&(level[i].clone() + &level[i+1])).unwrap())
            };

            next_level.push(pair_hash);
        }
        level = next_level;
    } 

    Some(level[0].clone())  

}

#[allow(warnings)]
fn hash_25(input: &[u8]) -> String {
    let h1 = Sha256::digest(input);
    let h2 = Sha256::digest(&h1);
    hex::encode(h2)
}

// pub fn compare_difficulty(difficulty: &str, hash: &str) -> Result<Ordering, ParseIntError> {
//     let difficulty_int = i128::from_str_radix(difficulty, 16)?;
//     let hash_int = i128::from_str_radix(hash, 16)?;

//     Ok(difficulty_int.cmp(&hash_int))
// }

pub fn calculate_witness_commitment(wtx_ids: Vec<String>) -> String {
    let witness_root = generate_merkel_root(wtx_ids.iter().map(|s| s.as_str()).collect()).unwrap();
    let witness_reserved_value = "0000000000000000000000000000000000000000000000000000000000000000";
    hash_25(&hex::decode(witness_root + witness_reserved_value).unwrap())
}

pub fn prepend_to_file(filename: &str, content: &str) -> io::Result<()>  {

    let mut file = OpenOptions::new().read(true).write(true).open(filename)?;
    let mut existing_content = String::new();
    file.read_to_string(&mut existing_content)?;

    file.seek(io::SeekFrom::Start(0))?;

    file.write_all(content.as_bytes())?;
    file.write_all(existing_content.as_bytes())?;

    Ok(())
}