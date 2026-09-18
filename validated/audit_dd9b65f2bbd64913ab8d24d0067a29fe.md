## Analog Found

### Title
Admin-controlled `PoolState.status` bit can permanently block LPs from withdrawing their funds - ([File: programs/cp-swap/src/instructions/withdraw.rs])

### Summary
The `withdraw()` instruction is the sole path an LP has to redeem their `owner_lp_token` for the underlying `token_0`/`token_1` (including any protocol-side accrued value baked into the vault balances). This path is gated by a single bitwise status flag on `PoolState` that only the hardcoded `admin::ID` can set, with no timelock, no LP-facing override, and no expiry. This mirrors the Napier `Tranche.pause()`/`collect()` pattern in the source report: a single admin-controlled switch that can be flipped on and never off (from the perspective of the affected users), permanently denying users access to funds they are otherwise entitled to.

### Finding Description
`PoolState.status` is a bitmask where bit1 disables withdraw [1](#0-0) . It is set exclusively through the `update_pool_status` instruction, which is restricted to the program's `admin::ID` signer and accepts any arbitrary `status` value up to 255: [2](#0-1) 

The `withdraw` instruction, which is the only mechanism for an LP to burn their LP tokens and reclaim the underlying `token_0_vault`/`token_1_vault` balances, checks this exact bit and unconditionally reverts if it is disabled: [3](#0-2) 

There is no other instruction in the program that lets an LP redeem their LP tokens for the underlying vault assets. If the admin sets bit1 (disable withdraw) and never unsets it, every LP's principal (and any yield accrued via the constant-product invariant, since fees remain in the vault and increase `vault_amount_without_fee`) becomes permanently locked, exactly analogous to how `Tranche.pause()` permanently blocked `collect()` for yield-bearing token holders in the referenced report.

### Impact Explanation
This causes a permanent freezing of LP funds. Every liquidity provider in every pool sharing that `AmmConfig`/`PoolState` is unable to exit their position or realize their share of accumulated trading fees baked into the pool's vault balances, with no fallback mechanism, no time-bound to the pause, and no way for LPs to self-rescue. Per the same reasoning accepted in the source Sherlock judgment, a "RESTRICTED" admin causing an unbounded, unilateral, permanent loss-of-access to user funds is a valid Medium-severity centralization/DoS finding, not merely an accepted design tradeoff — provided this restriction and its risk are not explicitly disclosed and bounded by the protocol.

### Likelihood Explanation
Reaching the vulnerable state requires only the admin issuing a single `update_pool_status` transaction (a normal, in-scope program instruction) with `status` having bit1 set. From that point on, any unprivileged LP attempting `withdraw()` — a completely permissionless, expected user action — is deterministically blocked by the `get_status_by_bit(PoolStatusBitIndex::Withdraw)` check with no time-based recovery.

### Recommendation
Consider bounding the pause: e.g., allow an emergency exit path for LPs regardless of the withdraw-disabled bit (perhaps at a penalty or without swap-related side effects), enforce a maximum pause duration/timelock, or require multisig/governance rather than a single `admin::ID` key to toggle `PoolState.status`. At minimum, explicitly document this centralization risk so it is treated as a disclosed, accepted restriction rather than an unbounded privileged capability.

### Proof of Concept
1. Admin calls `update_pool_status(pool_state, status=2)` (bit1 set → withdraw disabled) via the `crate::admin::ID`-restricted instruction [4](#0-3) .
2. Any LP holding `owner_lp_token` calls `withdraw(pool_state, lp_token_amount, ...)`.
3. The instruction hits `if !pool_state.get_status_by_bit(PoolStatusBitIndex::Withdraw) { return err!(ErrorCode::NotApproved); }` and reverts [5](#0-4) .
4. Admin never re-enables the bit (or is compromised/malicious) — LPs' tokens are burned nowhere, and the underlying `token_0_vault`/`token_1_vault` balances remain forever inaccessible to them since no other instruction can redeem LP tokens.

### Citations

**File:** programs/cp-swap/src/states/pool.rs (L92-97)
```rust
    pub auth_bump: u8,
    /// Bitwise representation of the state of the pool
    /// bit0, 1: disable deposit(value is 1), 0: normal
    /// bit1, 1: disable withdraw(value is 2), 0: normal
    /// bit2, 1: disable swap(value is 4), 0: normal
    pub status: u8,
```

**File:** programs/cp-swap/src/instructions/admin/update_pool_status.rs (L1-21)
```rust
use crate::states::*;
use anchor_lang::prelude::*;

#[derive(Accounts)]
pub struct UpdatePoolStatus<'info> {
    #[account(
        address = crate::admin::ID
    )]
    pub authority: Signer<'info>,

    #[account(mut)]
    pub pool_state: AccountLoader<'info, PoolState>,
}

pub fn update_pool_status(ctx: Context<UpdatePoolStatus>, status: u8) -> Result<()> {
    require_gte!(255, status);
    let mut pool_state = ctx.accounts.pool_state.load_mut()?;
    pool_state.set_status(status);
    pool_state.recent_epoch = Clock::get()?.epoch;
    Ok(())
}
```

**File:** programs/cp-swap/src/instructions/withdraw.rs (L105-111)
```rust
    require_gt!(lp_token_amount, 0);
    require_gte!(ctx.accounts.owner_lp_token.amount, lp_token_amount);
    let pool_id = ctx.accounts.pool_state.key();
    let pool_state = &mut ctx.accounts.pool_state.load_mut()?;
    if !pool_state.get_status_by_bit(PoolStatusBitIndex::Withdraw) {
        return err!(ErrorCode::NotApproved);
    }
```
