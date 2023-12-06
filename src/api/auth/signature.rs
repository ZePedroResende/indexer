use ethers_contract_derive::{Eip712, EthAbiType};
use ethers_core::types::transaction::eip712::TypedData;
use ethers_core::types::Signature;
use ethers_core::types::{transaction::eip712::Eip712, Address};
use ethers_signers::{coins_bip39::English, MnemonicBuilder, Signer};
use std::error::Error;
use std::str::FromStr;

async fn sign_type_data(data: SignatureData) -> Result<Signature, Box<dyn Error>> {
    let mnemonic = String::from("test test test test test test test test test test test junk");
    let derivation_path = String::from("m/44'/60'/0'/0");
    let current_path = format!("{}/{}", derivation_path, 0);
    let chain_id = 1_u32;
    let signer = MnemonicBuilder::<English>::default()
        .phrase(mnemonic.as_ref())
        .derivation_path(&current_path)?
        .build()
        .map(|v| v.with_chain_id(chain_id))?;

    let signature = signer.sign_typed_data(&data).await?;
    //let bytes = Bytes::from_hex(hex::encode(signature.to_vec()).as_bytes())?;
    Ok(signature)
}

//.encode_eip712().
#[derive(Debug, Clone, Eip712, EthAbiType)]
#[eip712(
    name = "IndexSignature",
    version = "1",
    chain_id = 1,
    verifying_contract = "0x0000000000000000000000000000000000000000"
)]
struct SignatureData {
    address: Address,
    current_timestamp: u64,
    expiration_timestamp: u64,
}

fn check_type_data(
    signature: Signature,
    address: Address,
    current_timestamp: u64,
    expiration_timestamp: u64,
) -> Result<(), Box<dyn Error>> {
    let data: SignatureData = SignatureData {
        address,
        current_timestamp,
        expiration_timestamp,
    }
    .into();

    let encoded = data.encode_eip712()?;

    signature.verify(encoded, address)?;

    Ok(())
}

#[cfg(test)]
mod test {
    use super::*;

    #[tokio::test]
    async fn test_signature() -> Result<(), Box<dyn Error>> {
        let current_timestamp = 1;
        let expiration_timestamp = 2;
        let address: Address =
            Address::from_str("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();

        let data: SignatureData = SignatureData {
            address,
            current_timestamp,
            expiration_timestamp,
        }
        .into();

        let signature = sign_type_data(data).await?;

        check_type_data(signature, address, current_timestamp, expiration_timestamp)?;
        Ok(())
    }

    #[tokio::test]
    async fn test_encoding() -> Result<(), Box<dyn Error>> {
        let json = serde_json::json!( {
          "types": {
            "EIP712Domain": [
              {
                "name": "name",
                "type": "string"
              },
              {
                "name": "version",
                "type": "string"
              },
              {
                "name": "chainId",
                "type": "uint256"
              },
              {
                "name": "verifyingContract",
                "type": "address"
              }
            ],
            "SignatureData": [
              {
                "name": "address",
                "type": "address"
              },
              {
                "name": "currentTimestamp",
                "type": "uint64"
              },
              {
                "name": "expirationTimestamp",
                "type": "uint64"
              }
            ]
          },
          "primaryType": "SignatureData",
          "domain": {
            "name": "IndexSignature",
            "version": "1",
            "chainId": "1",
            "verifyingContract": "0x0000000000000000000000000000000000000000",
          },
          "message": {
            "address": "0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266",
            "currentTimestamp": 1,
            "expirationTimestamp": 2
          }
        });

        let typed_data: TypedData = serde_json::from_value(json).unwrap();
        let hash = typed_data.encode_eip712().unwrap();

        let current_timestamp = 1;
        let expiration_timestamp = 2;
        let address: Address =
            Address::from_str("0xf39fd6e51aad88f6f4ce6ab8827279cfffb92266").unwrap();

        let data: SignatureData = SignatureData {
            address,
            current_timestamp,
            expiration_timestamp,
        }
        .into();

        let encoded = data.encode_eip712()?;

        assert_eq!(encoded, hash);
        Ok(())
    }
}
