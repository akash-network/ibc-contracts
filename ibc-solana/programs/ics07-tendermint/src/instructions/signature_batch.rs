// SPDX-License-Identifier: Apache-2.0
use crate::{error::ErrorCode, state::SignatureBatch, types::AppState};
use anchor_lang::prelude::*;
use solana_ibc_types::ics07::{SignatureData, SIGNATURE_BATCH_CAPACITY, SIGNATURE_BATCH_VERSION};

#[derive(Accounts)]
#[instruction(session: [u8; 32])]
pub struct InitializeSignatureBatch<'info> {
    #[account(init, payer = submitter, space = 8 + SignatureBatch::INIT_SPACE,
        seeds = [SignatureBatch::SEED, submitter.key().as_ref(), &session], bump)]
    pub signature_batch: Account<'info, SignatureBatch>,
    #[account(seeds = [AppState::SEED], bump)]
    pub app_state: Account<'info, AppState>,
    /// CHECK: program-owned access-manager PDA, checked by require_role.
    #[account(seeds = [access_manager::state::AccessManager::SEED], bump,
        seeds::program = app_state.am_state.access_manager)]
    pub access_manager: AccountInfo<'info>,
    #[account(mut)]
    pub submitter: Signer<'info>,
    /// CHECK: real instructions sysvar, used by role validation.
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions_sysvar: AccountInfo<'info>,
    pub system_program: Program<'info, System>,
}

pub fn initialize_signature_batch(
    ctx: Context<InitializeSignatureBatch>,
    session: [u8; 32],
) -> Result<()> {
    access_manager::require_role(
        &ctx.accounts.access_manager,
        solana_ibc_types::roles::RELAYER_ROLE,
        &ctx.accounts.submitter,
        &ctx.accounts.instructions_sysvar,
        &crate::ID,
    )?;
    let batch = &mut ctx.accounts.signature_batch;
    batch.version = SIGNATURE_BATCH_VERSION;
    batch.submitter = ctx.accounts.submitter.key();
    batch.session = session;
    batch.bump = ctx.bumps.signature_batch;
    batch.hashes = Vec::new();
    Ok(())
}

#[derive(Accounts)]
pub struct PreVerifySignatureBatch<'info> {
    #[account(mut, has_one = submitter, seeds = [SignatureBatch::SEED, submitter.key().as_ref(), &signature_batch.session],
        bump = signature_batch.bump)]
    pub signature_batch: Account<'info, SignatureBatch>,
    #[account(seeds = [AppState::SEED], bump)]
    pub app_state: Account<'info, AppState>,
    /// CHECK: access-manager PDA and role checked below.
    #[account(seeds = [access_manager::state::AccessManager::SEED], bump,
        seeds::program = app_state.am_state.access_manager)]
    pub access_manager: AccountInfo<'info>,
    pub submitter: Signer<'info>,
    /// CHECK: exact sysvar address, validated inline Ed25519 offsets.
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions_sysvar: AccountInfo<'info>,
}

pub fn pre_verify_signature_batch(
    ctx: Context<PreVerifySignatureBatch>,
    signature: SignatureData,
) -> Result<()> {
    access_manager::require_role(
        &ctx.accounts.access_manager,
        solana_ibc_types::roles::RELAYER_ROLE,
        &ctx.accounts.submitter,
        &ctx.accounts.instructions_sysvar,
        &crate::ID,
    )?;
    require!(
        ctx.accounts.signature_batch.to_account_info().data_len()
            == solana_ibc_types::ics07::SIGNATURE_BATCH_SIZE,
        ErrorCode::InvalidAccountData
    );
    require!(
        ctx.accounts
            .signature_batch
            .valid_identity(&ctx.accounts.signature_batch.key()),
        ErrorCode::InvalidAccountData
    );
    let digest =
        solana_sha256_hasher::hashv(&[&signature.pubkey, &signature.msg, &signature.signature])
            .to_bytes();
    require!(
        digest == signature.signature_hash,
        ErrorCode::InvalidAccountData
    );
    require!(
        super::pre_verify_signatures::verify_ed25519_from_sysvar(
            &ctx.accounts.instructions_sysvar,
            &signature.pubkey,
            &signature.msg,
            &signature.signature
        )?,
        ErrorCode::InvalidAccountData
    );
    // Verify even on retry; a full batch still accepts an authenticated duplicate.
    let batch = &mut ctx.accounts.signature_batch;
    if let Err(index) = batch.hashes.binary_search(&digest) {
        require!(
            batch.hashes.len() < SIGNATURE_BATCH_CAPACITY,
            ErrorCode::InvalidAccountData
        );
        batch.hashes.insert(index, digest);
    }
    Ok(())
}
