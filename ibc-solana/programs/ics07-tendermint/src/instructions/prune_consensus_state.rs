// SPDX-License-Identifier: Apache-2.0
// Local AKT extension: rent reclamation for expired consensus states.
use crate::error::ErrorCode;
use crate::state::ConsensusStateStore;
use crate::types::{AppState, ClientState};
use anchor_lang::prelude::*;

/// Closes one consensus state that is expired and not at the latest height,
/// returning its rent to the relayer. Mirrors ibc-go's expired-state pruning.
#[derive(Accounts)]
#[instruction(height: u64)]
pub struct PruneConsensusState<'info> {
    /// Supplies the latest height and trusting period.
    #[account(seeds = [ClientState::SEED], bump)]
    pub client_state: Account<'info, ClientState>,

    /// Provides the `access_manager` address for the role check.
    #[account(seeds = [AppState::SEED], bump)]
    pub app_state: Account<'info, AppState>,

    /// CHECK: Validated by seeds constraint using stored `access_manager` program ID
    #[account(
        seeds = [access_manager::state::AccessManager::SEED],
        bump,
        seeds::program = app_state.am_state.access_manager
    )]
    pub access_manager: AccountInfo<'info>,

    /// The consensus state to close.
    #[account(
        mut,
        close = submitter,
        seeds = [ConsensusStateStore::SEED, &height.to_le_bytes()],
        bump
    )]
    pub consensus_state_store: Account<'info, ConsensusStateStore>,

    /// Relayer holding `RELAYER_ROLE`; receives the reclaimed rent.
    #[account(mut)]
    pub submitter: Signer<'info>,

    /// CHECK: Address constraint verifies this is the instructions sysvar
    #[account(address = anchor_lang::solana_program::sysvar::instructions::ID)]
    pub instructions_sysvar: AccountInfo<'info>,
}

pub fn prune_consensus_state(ctx: Context<PruneConsensusState>, height: u64) -> Result<()> {
    access_manager::require_role(
        &ctx.accounts.access_manager,
        solana_ibc_types::roles::RELAYER_ROLE,
        &ctx.accounts.submitter,
        &ctx.accounts.instructions_sysvar,
        &crate::ID,
    )?;

    let client_state = &ctx.accounts.client_state;
    require!(
        height != client_state.latest_height.revision_height,
        ErrorCode::CannotPruneLatestConsensusState
    );

    let now = u64::try_from(Clock::get()?.unix_timestamp)
        .map_err(|_| error!(ErrorCode::ConsensusStateNotExpired))?;
    require!(
        is_expired(
            ctx.accounts.consensus_state_store.consensus_state.timestamp,
            client_state.trusting_period,
            now,
        ),
        ErrorCode::ConsensusStateNotExpired
    );

    Ok(())
}

/// ibc-go `IsExpired`: expired once `timestamp + trusting_period <= now`. The
/// verifier rejects such a state as a trust anchor for updates and misbehaviour.
pub(crate) const fn is_expired(
    timestamp_nanos: u64,
    trusting_period_secs: u64,
    now_secs: u64,
) -> bool {
    timestamp_nanos as u128 + trusting_period_secs as u128 * 1_000_000_000
        <= now_secs as u128 * 1_000_000_000
}

#[cfg(test)]
mod tests {
    use super::is_expired;

    #[test]
    fn expiry_boundary_matches_ibc_go() {
        let ts = 100_000_000_000; // 100 s
        assert!(!is_expired(ts, 10, 109));
        assert!(is_expired(ts, 10, 110));
        assert!(!is_expired(ts + 1, 10, 110));
        assert!(is_expired(u64::MAX - 1, 0, u64::MAX));
        assert!(!is_expired(u64::MAX, u64::MAX, u64::MAX));
    }
}
