use reth_primitives::Address;
use reth_primitives::Block;
use reth_primitives::Bytes;
use reth_primitives::Signature;
use reth_primitives::Transaction;
use reth_primitives::H256;
use reth_primitives::U256;

pub async fn sign_transaction(
    transaction: Transaction,
    private_key: H256,
) -> Result<Signature, String> {
    let signature = transaction.sign(&private_key);
    Ok(signature)
}

pub async fn check_signature(
    signature: Signature,
    public_key: Address,
    current_timestamp: U256,
    expiration_timestamp: U256,
) -> Result<bool, String> {
    let is_valid = signature.check(&public_key, current_timestamp, expiration_timestamp);
    Ok(is_valid)
}
