// SPDX-License-Identifier: Apache-2.0

//! ICS07 Tendermint light client types for Solana
//!
//! These types define the messages for the ICS07 Tendermint light client.

use anchor_lang::prelude::*;

pub use solana_ibc_constants::ASSEMBLE_UPDATE_CLIENT_STATIC_ACCOUNTS;

/// Update client message for ICS07 Tendermint
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct UpdateClientMsg {
    pub client_message: Vec<u8>, // Serialized Tendermint header
}

/// Ed25519 signature data for pre-verification
#[derive(AnchorSerialize, AnchorDeserialize, Clone, Debug)]
pub struct SignatureData {
    pub signature_hash: [u8; 32],
    pub pubkey: [u8; 32],
    pub msg: Vec<u8>,
    pub signature: [u8; 64],
}

/// Offset of `is_valid` field in `SignatureVerification` account data.
/// Equals Anchor discriminator length since `is_valid` is the first field.
pub const SIGNATURE_VERIFICATION_IS_VALID_OFFSET: usize =
    solana_ibc_constants::ANCHOR_DISCRIMINATOR_LEN;

// Local AKT extension. Existing individual receipt and membership ABIs stay unchanged.
pub const SIGNATURE_VERIFICATION_DISCRIMINATOR: [u8; 8] = [81, 117, 47, 112, 35, 80, 229, 151];
pub const SIGNATURE_BATCH_DISCRIMINATOR: [u8; 8] = [58, 220, 101, 246, 79, 152, 151, 56];
pub const SIGNATURE_BATCH_SEED: &[u8] = b"sig_batch";
pub const SIGNATURE_BATCH_VERSION: u8 = 1;
pub const SIGNATURE_BATCH_CAPACITY: usize = 128;
pub const SIGNATURE_BATCH_HASHES_OFFSET: usize = 78;
pub const SIGNATURE_BATCH_SIZE: usize =
    SIGNATURE_BATCH_HASHES_OFFSET + 32 * SIGNATURE_BATCH_CAPACITY;
pub const MAX_VERIFIER_BATCH_HASHES: usize = 256;
