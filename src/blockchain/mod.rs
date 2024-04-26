use chrono::Utc;

use crate::block::Block;

#[derive(Debug, Default)]
pub struct BlockChain {
    chain: Vec<Block>    
}

impl BlockChain {
    
    // Constructor
    pub fn new() -> Self {
        let chain: Vec<Block> = Vec::new();
        Self {
            chain
        }
    }

    fn create_genesisi_block(&self) -> Block {
        Block {
            version: 1,
            prev_block: hex::decode("0000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            merkel_root: hex::decode("000000000000000000000000000000000000000000000000000000000000000").unwrap(),
            timestamp:  (Utc::now().timestamp() / 1000) as u64,
            bits: hex::decode("ffff001d").unwrap(),
            nonce: hex::decode("0000000").unwrap(),
        }
    }

    fn add_block(&mut self, block: Block) {
        self.chain.push(block);
    }

    fn get_latest_block(&self) -> Block {
        self.chain[self.chain.len() - 1].clone()
    }
    
}