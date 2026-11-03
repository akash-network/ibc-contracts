// SPDX-License-Identifier: Apache-2.0

use anchor_lang::prelude::*;
use anchor_lang::Discriminator;

/// Closes incomplete `HeaderChunk` and `SignatureVerification` PDAs, returning
/// the rent to the original submitter.
///
/// Remaining accounts must be the chunk and signature verification PDAs to close.
#[derive(Accounts)]
pub struct CleanupIncompleteUpload<'info> {
    /// Original submitter who uploaded the chunks; must sign to prove ownership and receives rent refunds.
    #[account(mut)]
    pub submitter: Signer<'info>,
    // Remaining accounts are the chunk and signature verification accounts to close.
}

/// Cleans up incomplete update client uploads by closing both `HeaderChunk` and `SignatureVerification` PDAs
pub fn cleanup_incomplete_upload(ctx: Context<CleanupIncompleteUpload>) -> Result<()> {
    let submitter = ctx.accounts.submitter.key();

    for account in ctx.remaining_accounts {
        if account.owner != &crate::ID || account.lamports() == 0 {
            continue;
        }

        let should_close = is_owned_by_submitter(account, submitter)?;

        if should_close {
            crate::helpers::close_account(account, &ctx.accounts.submitter)?;
        }
    }

    Ok(())
}

/// Checks if an account is a `HeaderChunk` or `SignatureVerification` owned by the given submitter
pub(crate) fn is_owned_by_submitter(account: &AccountInfo, submitter: Pubkey) -> Result<bool> {
    let data = account.try_borrow_data()?;

    if data.len() < 8 {
        return Ok(false);
    }

    let disc = &data[..8];

    if disc == crate::state::SignatureBatch::DISCRIMINATOR {
        return Ok(data.len() == solana_ibc_types::ics07::SIGNATURE_BATCH_SIZE
            && u32::from_le_bytes(
                data[74..78]
                    .try_into()
                    .map_err(|_| crate::error::ErrorCode::InvalidAccountData)?,
            ) as usize
                <= solana_ibc_types::ics07::SIGNATURE_BATCH_CAPACITY
            && anchor_lang::AccountDeserialize::try_deserialize(&mut &data[..]).is_ok_and(
                |batch: crate::state::SignatureBatch| {
                    batch.submitter == submitter && batch.valid_identity(account.key)
                },
            ));
    }

    if disc == crate::state::HeaderChunk::DISCRIMINATOR {
        return Ok(
            anchor_lang::AccountDeserialize::try_deserialize(&mut &data[..])
                .is_ok_and(|chunk: crate::state::HeaderChunk| chunk.submitter == submitter),
        );
    }

    if disc == crate::state::SignatureVerification::DISCRIMINATOR {
        return Ok(
            anchor_lang::AccountDeserialize::try_deserialize(&mut &data[..])
                .is_ok_and(|sig: crate::state::SignatureVerification| sig.submitter == submitter),
        );
    }

    Ok(false)
}

#[cfg(test)]
mod tests;
