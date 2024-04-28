use chrono::Utc;
use crate::operations::hash256;

#[derive(Debug, Default, Clone)]
pub struct Block {
    pub version: u64,
    pub prev_block: Vec<u8>,
    pub merkel_root: Vec<u8>,
    pub timestamp: u64,
    pub bits: Vec<u8>,
    pub nonce: Vec<u8>,
}

impl Block {

    fn create_block(&self, merkel_root: &str, nonce: u32) -> String {
        let mut serialize = String::new();
        serialize += "11000000";
        serialize += &format!("{:0>64}", 0);
        serialize += merkel_root;
    
        let time = Utc::now().timestamp() as u32;
        let time_hex = format!("{:0>8}", format!("{:x}", time));

        let mut reversed_time = hex::decode(time_hex).unwrap();
        reversed_time.reverse();

        let reversed_time_hex = hex::encode(reversed_time);

        serialize += &reversed_time_hex;
        serialize += "ffff001f";
        serialize += &format!("{:0>8}", format!("{:x}", nonce));
    
        serialize
    }

    pub fn mine_block(&self, merkel_root: &str) -> String {
        let mut nonce = 0;
        let target_zeros = "0000";

        loop {
            let block = self.create_block(merkel_root, nonce);    
            let mut hash = hash256(&hex::decode(&block).unwrap());
            hash.reverse();

            let hash_hex = hex::encode(&hash);

            if hash_hex.starts_with(target_zeros) {
                return block;
            }

            nonce += 1;
        }
    }   

}