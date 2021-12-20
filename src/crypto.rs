// Copyright Rivtower Technologies LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use cita_cloud_proto::blockchain::raw_transaction::Tx::{NormalTx, UtxoTx};
use cita_cloud_proto::blockchain::{RawTransaction, RawTransactions};
use cloud_util::common::get_tx_hash;
use ctr::cipher::{generic_array::GenericArray, NewCipher, StreamCipher};
use prost::Message;
use status_code::StatusCode;
type Aes128Ctr = ctr::Ctr128BE<aes::Aes128>;

pub fn aes(password_hash: &[u8], data: &[u8]) -> Vec<u8> {
    let mut data = data.to_vec();

    let (key, nonce) = {
        let (key, nonce) = password_hash.split_at(16);

        (
            GenericArray::from_slice(key),
            GenericArray::from_slice(nonce),
        )
    };

    let mut cipher = Aes128Ctr::new(key, nonce);
    cipher.apply_keystream(&mut data);

    data
}

pub fn encrypt(password_hash: &[u8], data: &[u8]) -> Vec<u8> {
    aes(password_hash, data)
}

pub fn decrypt(password_hash: &[u8], data: &[u8]) -> Vec<u8> {
    aes(password_hash, data)
}

use tiny_keccak::{Hasher, Keccak};

pub const HASH_BYTES_LEN: usize = 32;

fn keccak_hash(input: &[u8]) -> [u8; HASH_BYTES_LEN] {
    let mut result = [0u8; HASH_BYTES_LEN];

    let mut keccak = Keccak::v256();
    keccak.update(input);
    keccak.finalize(&mut result);
    result
}

const SECP256K1_PUBKEY_BYTES_LEN: usize = 64;
const SECP256K1_PRIVKEY_BYTES_LEN: usize = 32;
pub const SECP256K1_SIGNATURE_BYTES_LEN: usize = 65;

lazy_static::lazy_static! {
    pub static ref SECP256K1: secp256k1::Secp256k1<secp256k1::All> = secp256k1::Secp256k1::new();
}

fn secp256k1_gen_keypair() -> Result<
    (
        [u8; SECP256K1_PUBKEY_BYTES_LEN],
        [u8; SECP256K1_PRIVKEY_BYTES_LEN],
    ),
    StatusCode,
> {
    let context = &SECP256K1;
    let (sec_key, pub_key) = context.generate_keypair(&mut rand::thread_rng());

    let serialized = pub_key.serialize_uncompressed();
    let mut pub_key = [0u8; SECP256K1_PUBKEY_BYTES_LEN];
    pub_key.copy_from_slice(&serialized[1..65]);

    let mut priv_key = [0u8; SECP256K1_PRIVKEY_BYTES_LEN];
    priv_key.copy_from_slice(&sec_key[0..32]);

    Ok((pub_key, priv_key))
}

fn secp256k1_sign(
    privkey: &[u8],
    msg: &[u8],
) -> Result<[u8; SECP256K1_SIGNATURE_BYTES_LEN], StatusCode> {
    let context = &SECP256K1;
    // no way to create from raw byte array.
    let sec = secp256k1::SecretKey::from_slice(privkey).unwrap();
    let s = context.sign_recoverable(&secp256k1::Message::from_slice(msg).unwrap(), &sec);
    let (rec_id, data) = s.serialize_compact();
    let mut data_arr = [0; SECP256K1_SIGNATURE_BYTES_LEN];

    // no need to check if s is low, it always is
    data_arr[0..SECP256K1_SIGNATURE_BYTES_LEN - 1]
        .copy_from_slice(&data[0..SECP256K1_SIGNATURE_BYTES_LEN - 1]);
    data_arr[SECP256K1_SIGNATURE_BYTES_LEN - 1] = rec_id.to_i32() as u8;
    Ok(data_arr)
}

fn secp256k1_recover(signature: &[u8], message: &[u8]) -> Result<Vec<u8>, StatusCode> {
    let context = &SECP256K1;
    if let Ok(rid) = secp256k1::recovery::RecoveryId::from_i32(i32::from(
        signature[SECP256K1_SIGNATURE_BYTES_LEN - 1],
    )) {
        if let Ok(rsig) = secp256k1::recovery::RecoverableSignature::from_compact(
            &signature[0..SECP256K1_SIGNATURE_BYTES_LEN - 1],
            rid,
        ) {
            if let Ok(publ) =
                context.recover(&secp256k1::Message::from_slice(message).unwrap(), &rsig)
            {
                let serialized = publ.serialize_uncompressed();
                return Ok(serialized[1..65].to_vec());
            }
        }
    }
    Err(StatusCode::SigCheckError)
}

pub fn generate_keypair() -> Result<(Vec<u8>, Vec<u8>), StatusCode> {
    let (pk, sk) = secp256k1_gen_keypair()?;
    Ok((pk.to_vec(), sk.to_vec()))
}

pub fn hash_data(data: &[u8]) -> Vec<u8> {
    keccak_hash(data).to_vec()
}

pub fn verify_data_hash(data: &[u8], hash: &[u8]) -> Result<(), StatusCode> {
    if hash.len() != HASH_BYTES_LEN {
        Err(StatusCode::HashLenError)
    } else if hash == hash_data(data) {
        Ok(())
    } else {
        Err(StatusCode::HashCheckError)
    }
}

pub const ADDR_BYTES_LEN: usize = 20;

pub fn sk2pk(sk: &[u8]) -> Vec<u8> {
    let context = &SECP256K1;
    let sec = secp256k1::SecretKey::from_slice(sk).unwrap();
    let pub_key = secp256k1::key::PublicKey::from_secret_key(context, &sec);
    let serialized = pub_key.serialize_uncompressed();
    serialized[1..].to_vec()
}

#[allow(dead_code)]
pub fn sk2address(sk: &[u8]) -> Vec<u8> {
    let pk = sk2pk(sk);
    pk2address(&pk)
}

pub fn pk2address(pk: &[u8]) -> Vec<u8> {
    hash_data(pk)[HASH_BYTES_LEN - ADDR_BYTES_LEN..].to_vec()
}

pub fn sign_message(_pubkey: &[u8], privkey: &[u8], msg: &[u8]) -> Result<Vec<u8>, StatusCode> {
    Ok(secp256k1_sign(privkey, msg)?.to_vec())
}

pub fn recover_signature(msg: &[u8], signature: &[u8]) -> Result<Vec<u8>, StatusCode> {
    if signature.len() != SECP256K1_SIGNATURE_BYTES_LEN {
        Err(StatusCode::SigLenError)
    } else {
        secp256k1_recover(signature, msg)
    }
}

#[allow(dead_code)]
pub fn check_transactions(raw_txs: &RawTransactions) -> StatusCode {
    use rayon::prelude::*;

    match tokio::task::block_in_place(|| {
        raw_txs
            .body
            .par_iter()
            .map(|raw_tx| {
                check_transaction(raw_tx).map_err(|status| {
                    log::warn!(
                        "check_raw_tx tx(0x{}) failed: {}",
                        hex::encode(get_tx_hash(raw_tx).unwrap()),
                        status
                    );
                    status
                })?;

                Ok(())
            })
            .collect::<Result<(), StatusCode>>()
    }) {
        Ok(()) => StatusCode::Success,
        Err(status) => status,
    }
}

#[allow(dead_code)]
fn check_transaction(raw_tx: &RawTransaction) -> Result<(), StatusCode> {
    match raw_tx.tx.as_ref() {
        Some(NormalTx(normal_tx)) => {
            if normal_tx.witness.is_none() {
                return Err(StatusCode::NoneWitness);
            }

            let witness = normal_tx.witness.as_ref().unwrap();
            let signature = &witness.signature;
            let sender = &witness.sender;

            let mut tx_bytes: Vec<u8> = Vec::new();
            if let Some(tx) = &normal_tx.transaction {
                tx.encode(&mut tx_bytes).map_err(|_| {
                    log::warn!("check_raw_tx: encode transaction failed");
                    StatusCode::EncodeError
                })?;
            } else {
                return Err(StatusCode::NoneTransaction);
            }

            let tx_hash = &normal_tx.transaction_hash;

            verify_data_hash(&tx_bytes, tx_hash)?;

            if &pk2address(&recover_signature(tx_hash, signature)?) == sender {
                Ok(())
            } else {
                Err(StatusCode::SigCheckError)
            }
        }
        Some(UtxoTx(utxo_tx)) => {
            let witnesses = &utxo_tx.witnesses;

            // limit witnesses length is 1
            if witnesses.len() != 1 {
                return Err(StatusCode::InvalidWitness);
            }

            let mut tx_bytes: Vec<u8> = Vec::new();
            if let Some(tx) = utxo_tx.transaction.as_ref() {
                tx.encode(&mut tx_bytes).map_err(|_| {
                    log::warn!("check_raw_tx: encode utxo failed");
                    StatusCode::EncodeError
                })?;
            } else {
                return Err(StatusCode::NoneUtxo);
            }

            let tx_hash = &utxo_tx.transaction_hash;
            verify_data_hash(&tx_bytes, tx_hash)?;

            for (_i, w) in witnesses.iter().enumerate() {
                let signature = &w.signature;
                let sender = &w.sender;

                if &pk2address(&recover_signature(tx_hash, signature)?) != sender {
                    return Err(StatusCode::SigCheckError);
                }
            }
            Ok(())
        }
        None => Err(StatusCode::NoneRawTx),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aes_test() {
        let password_hash = &keccak_hash("password".as_bytes());
        let data = vec![1u8, 2, 3, 4, 5, 6, 7];

        let cipher_message = aes(password_hash, &data);
        let decrypted_message = aes(password_hash, &cipher_message);
        assert_eq!(data, decrypted_message);
    }

    #[test]
    fn keccak_test() {
        let hash_empty: [u8; HASH_BYTES_LEN] = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ];
        assert_eq!(keccak_hash(&[]), hash_empty);
    }

    #[test]
    fn test_data_hash() {
        let data = vec![1u8, 2, 3, 4, 5, 6, 7];
        let hash = hash_data(&data);
        assert!(verify_data_hash(&data, &hash).is_ok());
    }

    #[test]
    fn test_signature() {
        // message must be 32 bytes
        let data: [u8; HASH_BYTES_LEN] = [
            0xc5, 0xd2, 0x46, 0x01, 0x86, 0xf7, 0x23, 0x3c, 0x92, 0x7e, 0x7d, 0xb2, 0xdc, 0xc7,
            0x03, 0xc0, 0xe5, 0x00, 0xb6, 0x53, 0xca, 0x82, 0x27, 0x3b, 0x7b, 0xfa, 0xd8, 0x04,
            0x5d, 0x85, 0xa4, 0x70,
        ];

        let (pubkey, privkey) = generate_keypair().unwrap();
        let signature = sign_message(&pubkey, &privkey, &data).unwrap();
        assert_eq!(recover_signature(&data, &signature), Ok(pubkey));
    }
}
