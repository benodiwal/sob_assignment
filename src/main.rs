use std::{fs::File, io::Write};

use block::Block;
use transactions::load_transactions_from_mempool;
use utils::prepend_to_file;
use crate::transactions::verify_p2pkh_transactions;

mod transactions;
mod utils;
mod operations;
mod scripts;
mod block;
mod blockchain;

fn main() -> Result<(), Box<dyn std::error::Error>> {
        let transactions = load_transactions_from_mempool("mempool")?;
    // verify_p2pkh_transactions(transactions);

    let mut file = File::create("output.txt")?; 
    let block = Block::default();
    let block_header = block.mine_block(&verify_p2pkh_transactions(transactions, &mut file));

    // file.write_all(block_header.as_bytes())?; 
    prepend_to_file("output.txt", &(block_header + "\n"))?;

    file.flush()?;

    Ok(())
}