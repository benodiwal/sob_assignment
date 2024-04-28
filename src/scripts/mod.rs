use crate::operations::{hash_160, hash_256, op_0, op_1, op_2, op_3, op_check_multi_sig, op_check_sig, op_check_sig_verify, op_dup, op_equal, op_equal_verify, op_ripemd160, op_sha1, op_sha256};

#[derive(PartialEq, Eq, Debug, Clone)]
enum Operation {
    PushBytes(Vec<u8>),
    Ripemd160,
    Sha1,
    Sha256,
    Hash160,
    Hash256,
    Zero,
    One,
    Two,
    Three,
    CheckSigVerify,
    CheckSig,
    Verify,
    Equal,
    EqualVerify,
    Dup,
    CheckMultiSig,
}

fn parse_script(script: Vec<&str>) -> Vec<Operation> {
    let mut operations: Vec<Operation> = Vec::new();

    for i in 0..script.len() {
        if script[i].starts_with("OP_PUSHBYTES_") && i+1 < script.len() {
            operations.push(Operation::PushBytes(hex::decode(script[i+1]).unwrap()));
        } else {
            match script[i] {
                "OP_DUP" => {
                    operations.push(Operation::Dup);
                },
                "OP_HASH160" => {
                    operations.push(Operation::Hash160);
                },
                "OP_EQUALVERIFY" => {
                    operations.push(Operation::EqualVerify);
                },
                "OP_EQUAL" => {
                    operations.push(Operation::Equal);
                },
                "OP_HASH256" => {
                    operations.push(Operation::Hash256);
                },
                "OP_SHA1"  => {
                    operations.push(Operation::Sha1);
                },
                "OP_SHA256" => {
                    operations.push(Operation::Sha256);
                },
                "OP_0" => {
                    operations.push(Operation::Zero);
                },
                "OP_1" => {
                    operations.push(Operation::One);
                },
                "OP_2" => {
                    operations.push(Operation::Two);
                },
                "OP_3" => {
                    operations.push(Operation::Three);
                },
                "OP_CHECKSIG" => {
                    operations.push(Operation::CheckSig);
                },
                "OP_CHECKSIGVERIFY" => {
                    operations.push(Operation::CheckSigVerify);
                },
                "OP_VERIFY" => {
                    operations.push(Operation::Verify);
                },
                "OP_CHECKMULTISIG" => {
                    operations.push(Operation::CheckMultiSig);
                },
                "OP_RIPEMD160" => {
                    operations.push(Operation::Ripemd160);
                },
                _ => {}
            }
        }
    }

    operations
}

#[allow(warnings)]
pub fn verify_script(mut script: Vec<&str>, z: Vec<u8>) -> bool {
    let mut stack: Vec<Vec<u8>> = Vec::new();
    println!("{:?}", parse_script(script.clone()));

    for op in parse_script(script) {

        println!("{:?}", op);

        let res = match op {
            Operation::Dup => op_dup(&mut stack, &z),
            Operation::CheckMultiSig => op_check_multi_sig(&mut stack, &z),
            Operation::CheckSig => op_check_sig(&mut stack, &z),
            Operation::Equal => op_equal(&mut stack, &z),
            Operation::CheckSigVerify => op_check_sig_verify(&mut stack, &z),
            Operation::EqualVerify => op_equal_verify(&mut stack, &z),
            Operation::Hash160 => hash_160(&mut stack, &z),
            Operation::Hash256 => hash_256(&mut stack, &z),
            Operation::Ripemd160 => op_ripemd160(&mut stack, &z),
            Operation::Sha1 => op_sha1(&mut stack, &z),
            Operation::Sha256 => op_sha256(&mut stack, &z),
            Operation::Zero => op_0(&mut stack, &z),
            Operation::One => op_1(&mut stack, &z),
            Operation::Two => op_2(&mut stack, &z),
            Operation::Three => op_3(&mut stack, &z),
            Operation::PushBytes(val) => {
                stack.push(val);
                true
            }
            _ => false,
        };

        if !res {
            return false;
        }

    }

    if (stack.len() != 1) {
        return false;
    }

    if stack[0].len() != 0 && stack[0][0] == 1 {
        return true;
    } else {
        return false;
    }

}


pub fn is_p2pkh_lock(script: Vec<&str>) -> bool {
    let cmds = parse_script(script);

    if cmds.len() != 5 {
        return false;
    }

    if cmds[0] != Operation::Dup {
        return false;
    }

    if cmds[1] != Operation::Hash160 {
        return false;
    }

    let pub_key_hash = &cmds[2];
    if let Operation::PushBytes(pub_key_hash) = pub_key_hash {
        if pub_key_hash.len() != 20 {
            return false;
        }
    } else {
        return false;
    }

    if cmds[3] != Operation::EqualVerify {
        return false;
    }

    if cmds[4] != Operation::CheckSig {
        return false;
    }

    true
}

pub fn is_p2wpkh_lock(script: Vec<&str>) -> bool {
    let cmds = parse_script(script);

    if cmds.len() != 2 {
        return false;
    }

    if cmds[0] != Operation::Zero {
        return false;
    }

    let pub_key_hash = &cmds[1];
    if let Operation::PushBytes(pub_key_hash) = pub_key_hash {
        if pub_key_hash.len() != 20 {
            return false;
        }
    } else {
        return false;
    }

    true
}

pub fn p2pkhlock(pkh160: &[u8]) -> Vec<u8> {
    let mut buf: Vec<u8> = Vec::new();
    buf.append(&mut hex::decode("76").unwrap());
    buf.append(&mut hex::decode("a9").unwrap());
    buf.append(&mut pkh160.to_vec());
    buf.append(&mut hex::decode("88").unwrap());
    buf.append(&mut hex::decode("ac").unwrap());

    buf
}

pub fn p2pkhlock_cmds(pkh160: &[u8]) -> Vec<String> {
    vec!["OP_DUP".to_string(), "OP_HASH160".to_string(), "OP_PUSHBYTES_1".to_string(), hex::encode(pkh160), "OP_EQUALVERIFY".to_string(), "OP_CHECKSIG".to_string()]
}