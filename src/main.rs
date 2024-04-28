use transactions::load_transactions_from_mempool;

mod transactions;
mod utils;
mod operations;
mod scripts;
mod block;

fn main() -> Result<(), Box<dyn std::error::Error>> {
        let transactions = load_transactions_from_mempool("mempool")?;
    // verify_p2pkh_transactions(transactions);

    // let mut file = File::create("output.txt")?; 
    // let block = Block::default();
    // let block_header = block.mine_block(&verify_p2pkh_transactions(transactions, &mut file));

    // // file.write_all(block_header.as_bytes())?; 
    // prepend_to_file("output.txt", &(block_header + "\n"))?;

    // file.flush()?;

    Ok(())
}