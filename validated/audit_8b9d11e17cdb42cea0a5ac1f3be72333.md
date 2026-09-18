### Title
Pool-pause (`status`) bitmask is enforced on deposit/withdraw/swap but never checked in `collect_creator_fee` / `collect_creator_fee_permissionless` - (File: `programs/cp-swap/src/instructions/collect_creator_fee.rs`, `programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs`)

### Summary
Raydium's `PoolState.status` bitmask lets the admin disable deposit, withdraw, and swap operations on a per-pool basis via `get_status_by_bit`. Every fund-movement instruction that touches user or LP tokens checks this bitmask before transferring, except the two creator-fee-collection instructions, which transfer accumulated fees out of the pool vaults unconditionally.

### Finding Description
`deposit.rs`, `withdraw.rs`, `swap_base_input.rs`, and `swap_base_output.rs` each call `pool_state.get_status_by_bit(...)` before moving tokens, so an admin can pause any of these flows on a specific pool (e.g., in response to a detected exploit or oracle manipulation) [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) .

`collect_creator_fee` and `collect_creator_fee_permissionless`, however, never inspect `pool_state.status` at all. Both handlers only check that accumulated `creator_fees_token_0`/`creator_fees_token_1` are non-zero and then call `transfer_from_pool_vault_to_user` twice, draining those amounts out of `token_0_vault`/`token_1_vault`: [5](#0-4) [6](#0-5) 

This is the same class of bug as the Portainer advisory: an administrator-configured, security-relevant restriction (`EndpointSecuritySettings` there, the pool `status` pause bitmask here) is enforced on the "primary" set of routes (container/service create in Portainer; deposit/withdraw/swap here) but silently skipped on a structurally similar route (service update in Portainer; creator-fee collection here) that still moves value out of the protected resource. Because `collect_creator_fee_permissionless` can be invoked by *any* signer (only the destination `creator` account is constrained, `payer` can be anyone), the fee drain can be triggered even while the pool is supposed to be frozen, without needing the creator's cooperation.

### Impact Explanation
If an admin pauses a pool (e.g., disables withdraw/swap while investigating a suspected drained/insolvent pool, a bad price feed, or a compromised token mint) with the intent of freezing all outbound vault transfers, the accrued creator-fee balance can still be pulled out of the live `token_0_vault`/`token_1_vault` via `collect_creator_fee_permissionless`, since it is not gated by `get_status_by_bit`. This undermines the pause control's guarantee that vault outflows stop, and — depending on how large `creator_fees_token_0/1` has grown — can materially reduce the vault balance the admin is trying to protect during an incident, directly analogous to the Portainer bypass where an administrator-configured restriction fails to apply uniformly across equivalent operations.

### Likelihood Explanation
Any account can call `collect_creator_fee_permissionless` at any time as long as `creator_fees_token_0`/`creator_fees_token_1` are non-zero; no special privilege, signature from the pool creator, or unusual account setup is required. The only precondition is that the admin has paused the pool via the status bitmask and unclaimed creator fees exist — a realistic, easily reachable scenario for any actively-traded pool.

### Recommendation
Add the same `pool_state.get_status_by_bit(PoolStatusBitIndex::Withdraw)` (or a dedicated bit) check used in `withdraw.rs`/`swap_base_input.rs`/`swap_base_output.rs`/`deposit.rs` to both `collect_creator_fee` and `collect_creator_fee_permissionless` before performing `transfer_from_pool_vault_to_user`, so that a paused pool blocks all vault outflows uniformly, closing the gap between the enforced and unenforced code paths.

### Proof of Concept
1. Pool is actively trading and has accrued non-zero `pool_state.creator_fees_token_0`/`creator_fees_token_1` from swaps.
2. Admin detects an issue and calls `update_pool_status` to set the pause bits that block deposit/withdraw/swap on this pool.
3. Any user submits a `collect_creator_fee_permissionless` transaction with `payer` = themselves and `creator` = the pool's recorded `pool_creator`.
4. The instruction passes all constraints (no `status` check exists), and `transfer_from_pool_vault_to_user` moves the full accrued fee amounts out of `token_0_vault`/`token_1_vault` to the creator's ATAs, despite the pool being "paused."

### Citations

**File:** programs/cp-swap/src/instructions/withdraw.rs (L1-1)
```rust
use crate::curve::CurveCalculator;
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L1-1)
```rust
use crate::curve::calculator::CurveCalculator;
```

**File:** programs/cp-swap/src/instructions/swap_base_output.rs (L1-1)
```rust
use super::swap_base_input::Swap;
```

**File:** programs/cp-swap/src/instructions/deposit.rs (L1-1)
```rust
use crate::curve::CurveCalculator;
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L88-118)
```rust
pub fn collect_creator_fee(ctx: Context<CollectCreatorFee>) -> Result<()> {
    let mut pool_state = ctx.accounts.pool_state.load_mut()?;
    let creator_fees_token_0 = pool_state.creator_fees_token_0;
    let creator_fees_token_1 = pool_state.creator_fees_token_1;
    if creator_fees_token_0 == 0 && creator_fees_token_1 == 0 {
        return err!(ErrorCode::NoFeeCollect);
    }

    let signer_seeds: &[&[u8]] = &[crate::AUTH_SEED.as_bytes(), &[ctx.bumps.authority]];

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.creator_token_0.to_account_info(),
        ctx.accounts.vault_0_mint.to_account_info(),
        ctx.accounts.token_0_program.to_account_info(),
        creator_fees_token_0,
        ctx.accounts.vault_0_mint.decimals,
        &[signer_seeds],
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_1_vault.to_account_info(),
        ctx.accounts.creator_token_1.to_account_info(),
        ctx.accounts.vault_1_mint.to_account_info(),
        ctx.accounts.token_1_program.to_account_info(),
        creator_fees_token_1,
        ctx.accounts.vault_1_mint.decimals,
        &[signer_seeds],
    )?;
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L91-123)
```rust
pub fn collect_creator_fee_permissionless(
    ctx: Context<CollectCreatorFeePermissionless>,
) -> Result<()> {
    let mut pool_state = ctx.accounts.pool_state.load_mut()?;
    let creator_fees_token_0 = pool_state.creator_fees_token_0;
    let creator_fees_token_1 = pool_state.creator_fees_token_1;
    if creator_fees_token_0 == 0 && creator_fees_token_1 == 0 {
        return err!(ErrorCode::NoFeeCollect);
    }

    let signer_seeds: &[&[u8]] = &[crate::AUTH_SEED.as_bytes(), &[ctx.bumps.authority]];

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.creator_token_0.to_account_info(),
        ctx.accounts.vault_0_mint.to_account_info(),
        ctx.accounts.token_0_program.to_account_info(),
        creator_fees_token_0,
        ctx.accounts.vault_0_mint.decimals,
        &[signer_seeds],
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_1_vault.to_account_info(),
        ctx.accounts.creator_token_1.to_account_info(),
        ctx.accounts.vault_1_mint.to_account_info(),
        ctx.accounts.token_1_program.to_account_info(),
        creator_fees_token_1,
        ctx.accounts.vault_1_mint.decimals,
        &[signer_seeds],
    )?;
```
