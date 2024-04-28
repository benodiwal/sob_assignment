use ripemd::{Digest, Ripemd160};
use sha1::Sha1;
use sha2::Sha256;
use libsecp256k1::{verify, Message, PublicKey, Signature};

pub fn op_ripemd160(stack: &mut Vec<Vec<u8>>, _: &[u8]) -> bool {
    if stack.is_empty() {
        return false;
    }

    let input = stack.pop().unwrap();
    let output = Ripemd160::digest(input);
    stack.push(output.to_vec());

    true
}

pub fn op_sha1(stack: &mut Vec<Vec<u8>>, _: &[u8]) -> bool {
    if stack.is_empty() {
        return false;
    }

    let input = stack.pop().unwrap();
    let output = Sha1::digest(input);
    stack.push(output.to_vec());
    
    true
}

pub fn op_sha256(stack: &mut Vec<Vec<u8>>, _: &[u8]) -> bool {
    if stack.is_empty() {
        return false;
    }

    let input = stack.pop().unwrap();
    let output = Sha256::digest(input);
    stack.push(output.to_vec());
    
    true
}

pub fn hash_160(stack: &mut Vec<Vec<u8>>, _: &[u8]) -> bool {
    if stack.is_empty() {
        return false;
    }

    let element = stack.pop().unwrap();
    stack.push(hash160(&element));

    println!("{:?}", stack);
    
    true
}

pub fn hash_256(stack: &mut Vec<Vec<u8>>, _: &[u8]) -> bool {
    if stack.is_empty() {
        return false;
    }

    let element = stack.pop().unwrap();
    stack.push(hash256(&element));
    
    true
}

pub fn op_0(stack: &mut Vec<Vec<u8>>, _: &[u8]) -> bool {
    stack.push(encode_num(0u64));
    
    true
}

pub fn op_1(stack: &mut Vec<Vec<u8>>, _: &[u8]) -> bool {
    stack.push(encode_num(1u64));
    true
}

pub fn op_2(stack: &mut Vec<Vec<u8>>, _: &[u8]) -> bool {
    stack.push(encode_num(2u64));
    true
}

pub fn op_3(stack: &mut Vec<Vec<u8>>, _: &[u8]) -> bool {
    stack.push(encode_num(3u64));
    true
}

pub fn op_check_sig_verify(stack: &mut Vec<Vec<u8>>, z: &[u8]) -> bool {
    op_check_sig(stack, z) && op_verify(stack, z)
}

pub fn op_check_sig(stack: &mut Vec<Vec<u8>>, z: &[u8]) -> bool {
    if stack.len() < 2 {
        return false;
    }

    stack.pop();

    let pk_buf = stack.pop().unwrap();
    let sig_buf = stack.pop().unwrap();

    let pk = match PublicKey::parse_slice(&pk_buf, None) {
        Ok(pk) => pk,
        Err(err) => {
            eprintln!("{:?}", err);
            op_0(stack, z);
            return true;
        }
    };

    let msg_hash = Message::parse_slice(z).unwrap();

    if sig_buf.is_empty() {
        op_0(stack, z);
        return true;
    }

    let sig = match Signature::parse_der_lax(&sig_buf[..sig_buf.len() - 1]) {
        Ok(sig) => sig,
        Err(err) => {
            eprintln!("{:?}", err);
            op_0(stack, z);
            return true;
        }
    };

    if verify(&msg_hash, &sig, &pk) {
        println!("Yes");
    } else {
        op_0(stack, z);
    }

    true
}

pub fn op_verify(stack: &mut Vec<Vec<u8>>, _: &[u8]) -> bool {
    if stack.is_empty() {
        return false;
    }

    let top = &stack[stack.len() - 1];

    if top.is_empty() {
        return false;
    }
   
    true
}

pub fn op_equal(stack: &mut Vec<Vec<u8>>, _: &[u8]) -> bool {
    if stack.len() < 2 {
        return false;
    }

    let a = stack.pop().unwrap();
    let b = stack.pop().unwrap();

    let result = a == b;

    if !result {
        op_0(stack, &[0]);
    } else {
        op_1(stack, &[0]);
    }

    true
}

pub fn op_equal_verify(stack: &mut Vec<Vec<u8>>, _: &[u8]) -> bool {
    println!("{:?}", stack.len());
    
    if !op_equal(stack, &[0]) {
        return false;
    }

    if !op_verify(stack, &[0]) {
        return false;
    }

    println!("{:?}", stack);

    true
}

pub fn op_dup(stack: &mut Vec<Vec<u8>>, _: &[u8]) -> bool {
    if stack.is_empty() {
        return false;
    }

    let top = stack.last().unwrap().clone();

    stack.push(top);
    println!("{:?}", stack);

    true
}

pub fn op_check_multi_sig(stack: &mut Vec<Vec<u8>>, z: &[u8]) -> bool {
    if stack.is_empty() {
        return false;
    }

    let n = decode_num(&stack.pop().unwrap());

    if stack.len() < n as usize {
        return false;
    }

    let mut sec_pub_keys = Vec::new();
    for _ in 0..n {
        sec_pub_keys.push(stack.pop().unwrap());
    }

    let m = decode_num(&stack.pop().unwrap());

    if stack.len() < m as usize {
        return false;
    }

    let mut der_sigs = Vec::new();
    for _ in 0..m {
        der_sigs.push(stack.pop().unwrap());
    }

    if stack.is_empty() {
        return false;
    }

    let mut verified_sigs = 0;
    for der_sig in der_sigs {
        let sig = match Signature::parse_der_lax(&der_sig) {
            Ok(sig) => sig,
            Err(_) => return false,
        };

        let mut verified_keys = 0;
        for sec_key in sec_pub_keys.iter().map(|s| PublicKey::parse_slice(&s, None).ok()).flatten() {
            if verify(&Message::parse_slice(z).unwrap(), &sig, &sec_key) {
                verified_keys += 1;
            }
        }

        if verified_keys > 0 {
            verified_sigs += 1;
        }
    }

    stack.push(encode_num(verified_sigs as u64));

    stack.pop();

    true
}

pub fn encode_num(num: u64) -> Vec<u8> {
    if num == 0 {
        return vec![];
    }

    let mut bytes = Vec::new();
    let mut abs = num;

    while abs > 0 {
        bytes.push((abs & 0xff) as u8);
        abs >>= 8;
    }

    if bytes.last().unwrap() & 0x80 != 0 {
        bytes.push(0x00);
    }

    bytes
}

pub fn decode_num(buf: &[u8]) -> i64 {
    if buf.is_empty() {
        return 0;
    }

    let mut be = buf.to_vec();
    be.reverse();

    let mut result = be[0] as i64;

    for i in 1..be.len() {
        result <<= 8;
        result |= be[i] as i64;
    }

    if be[0] & 0x80 != 0 {
        result |= -(1 << (8 * be.len()));
    }

    result
}

// Utils
fn hash160(buf: &Vec<u8>) -> Vec<u8> {
    let sha256_digest = Sha256::digest(buf);
    let ripemd160_digest = Ripemd160::digest(sha256_digest);
    ripemd160_digest.to_vec()
}

pub fn hash256(buf: &Vec<u8>) -> Vec<u8> {
    let sha256_digest = Sha256::digest(buf);
    let sha256_digest_next = Sha256::digest(sha256_digest);
    sha256_digest_next.to_vec()
}