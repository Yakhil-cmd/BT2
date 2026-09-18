### Title
Depositing liquidity is allowed even when withdrawal is paused, permanently locking LP funds until admin intervention - (File: `programs/cp-swap/src/instructions/deposit.rs`, `programs/cp-swap/src/instructions/withdraw.rs`, `programs/cp-swap/src/states/pool.rs`)

### Summary
`PoolState.status` encodes three independent bitwise flags — `Deposit`, `Withdraw`, and `Swap` — that the pool admin can toggle via `update_pool_status` [1](#0-0) . `deposit()` only checks the `Deposit` bit before pulling user tokens and minting LP tokens, with no check on the `Withdraw` bit [2](#0-1) . This lets any unprivileged LP deposit tokens into a pool whose `Withdraw` bit is disabled, minting them LP tokens they cannot redeem, because `withdraw()` independently checks the `Withdraw` bit and reverts with `NotApproved` [3](#0-2) .

### Finding Description
`PoolStatusBitIndex` defines `Deposit`, `Withdraw`, and `Swap` as independently settable/gettable bits [4](#0-3) , and `get_status_by_bit`/`set_status_by_bit` operate on each bit in isolation with no cross-bit invariant enforcement [5](#0-4) . An admin calling `update_pool_status` with a raw `status` byte (e.g. `2` to disable only `Withdraw`) leaves `Deposit` fully enabled [1](#0-0) .

Once `Withdraw` is disabled but `Deposit` remains enabled, any unprivileged liquidity provider can still call `deposit()`, transferring real token_0/token_1 into the pool vaults and receiving newly minted LP tokens [6](#0-5) . Those same LP tokens cannot be redeemed back for the underlying assets, since `withdraw()` reverts immediately with `ErrorCode::NotApproved` when the `Withdraw` bit is disabled [7](#0-6) . This is the exact analog of the referenced report: minting/depositing is not gated on the corresponding redemption/withdrawal pause flag, so users can enter a position from which they have no exit until the admin decides to re-enable withdrawals.

The entry point (`deposit`) is reachable by any unprivileged LP with attacker-chosen deposit amounts; the precondition (admin having disabled only the `Withdraw` bit while leaving `Deposit` enabled) is a legitimate, foreseeable operational state of the pool status bitmask, not a malicious/compromised-admin scenario — it's the normal partial-pause capability the bitmask explicitly supports.

### Impact Explanation
Users who deposit while `Withdraw` is disabled but `Deposit` remains enabled have their underlying token_0/token_1 locked in the pool vaults with no way to retrieve them via `withdraw()` until the admin flips the bit back. Given that pausing withdrawal is a documented emergency/maintenance control, users depositing during such a window (which they may not even be aware of, since deposit succeeds silently) can have their funds locked for an indefinite period at the sole discretion of the admin. This matches the fund-locking impact class of the referenced report.

### Likelihood Explanation
Likelihood is moderate: it requires the admin to disable `Withdraw` without also disabling `Deposit` via a single raw `status` byte, which is a plausible partial-pause configuration (e.g., pausing withdrawals during an incident investigation while still permitting deposits), combined with an unprivileged user calling `deposit()` during that window — no attacker privilege or complex setup is needed on the user side.

### Recommendation
Add a check in `deposit()` that also requires the `Withdraw` bit to be enabled (or otherwise enforce that `Deposit` cannot be enabled while `Withdraw` is disabled), e.g.:

```rust
if !pool_state.get_status_by_bit(PoolStatusBitIndex::Deposit)
    || !pool_state.get_status_by_bit(PoolStatusBitIndex::Withdraw)
{
    return err!(ErrorCode::NotApproved);
}
```

Alternatively, enforce the invariant at `update_pool_status` time so that `Deposit` can never be enabled while `Withdraw` is disabled.

### Proof of Concept
1. Pool is initialized normally; `status = 0` (all operations enabled).
2. Admin calls `update_pool_status(ctx, 2)` — this sets bit 1 (`Withdraw`), disabling withdrawals only, while `Deposit` (bit 0) and `Swap` (bit 2) remain enabled [8](#0-7) .
3. An unprivileged LP calls `deposit(lp_token_amount, max_0, max_1)`. `get_status_by_bit(PoolStatusBitIndex::Deposit)` returns `true`, so the check passes, tokens are transferred into the vaults, and LP tokens are minted to the user [9](#0-8) .
4. The same LP then calls `withdraw(lp_token_amount, ...)` to redeem their newly minted LP tokens. `get_status_by_bit(PoolStatusBitIndex::Withdraw)` returns `false`, so the call reverts with `ErrorCode::NotApproved` [7](#0-6) .
5. The LP's underlying tokens are now locked in the pool vaults with no way to retrieve them until the admin re-enables the `Withdraw` bit.

### Citations

**File:** programs/cp-swap/src/instructions/admin/update_pool_status.rs (L15-21)
```rust
pub fn update_pool_status(ctx: Context<UpdatePoolStatus>, status: u8) -> Result<()> {
    require_gte!(255, status);
    let mut pool_state = ctx.accounts.pool_state.load_mut()?;
    pool_state.set_status(status);
    pool_state.recent_epoch = Clock::get()?.epoch;
    Ok(())
}
```

**File:** programs/cp-swap/src/instructions/deposit.rs (L93-98)
```rust
    require_gt!(lp_token_amount, 0);
    let pool_id = ctx.accounts.pool_state.key();
    let pool_state = &mut ctx.accounts.pool_state.load_mut()?;
    if !pool_state.get_status_by_bit(PoolStatusBitIndex::Deposit) {
        return err!(ErrorCode::NotApproved);
    }
```

**File:** programs/cp-swap/src/instructions/deposit.rs (L164-201)
```rust
    transfer_from_user_to_pool_vault(
        ctx.accounts.owner.to_account_info(),
        ctx.accounts.token_0_account.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.vault_0_mint.to_account_info(),
        if ctx.accounts.vault_0_mint.to_account_info().owner == ctx.accounts.token_program.key {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        },
        transfer_token_0_amount,
        ctx.accounts.vault_0_mint.decimals,
    )?;

    transfer_from_user_to_pool_vault(
        ctx.accounts.owner.to_account_info(),
        ctx.accounts.token_1_account.to_account_info(),
        ctx.accounts.token_1_vault.to_account_info(),
        ctx.accounts.vault_1_mint.to_account_info(),
        if ctx.accounts.vault_1_mint.to_account_info().owner == ctx.accounts.token_program.key {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        },
        transfer_token_1_amount,
        ctx.accounts.vault_1_mint.decimals,
    )?;

    pool_state.lp_supply = pool_state.lp_supply.checked_add(lp_token_amount).unwrap();

    token_mint_to(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_program.to_account_info(),
        ctx.accounts.lp_mint.to_account_info(),
        ctx.accounts.owner_lp_token.to_account_info(),
        lp_token_amount,
        &[&[crate::AUTH_SEED.as_bytes(), &[pool_state.auth_bump]]],
    )?;
```

**File:** programs/cp-swap/src/instructions/withdraw.rs (L104-111)
```rust
) -> Result<()> {
    require_gt!(lp_token_amount, 0);
    require_gte!(ctx.accounts.owner_lp_token.amount, lp_token_amount);
    let pool_id = ctx.accounts.pool_state.key();
    let pool_state = &mut ctx.accounts.pool_state.load_mut()?;
    if !pool_state.get_status_by_bit(PoolStatusBitIndex::Withdraw) {
        return err!(ErrorCode::NotApproved);
    }
```

**File:** programs/cp-swap/src/states/pool.rs (L12-16)
```rust
pub enum PoolStatusBitIndex {
    Deposit,
    Withdraw,
    Swap,
}
```

**File:** programs/cp-swap/src/states/pool.rs (L184-198)
```rust
    pub fn set_status_by_bit(&mut self, bit: PoolStatusBitIndex, flag: PoolStatusBitFlag) {
        let s = u8::from(1) << (bit as u8);
        if flag == PoolStatusBitFlag::Disable {
            self.status = self.status.bitor(s);
        } else {
            let m = u8::from(255).bitxor(s);
            self.status = self.status.bitand(m);
        }
    }

    /// Get status by bit, if it is `noraml` status, return true
    pub fn get_status_by_bit(&self, bit: PoolStatusBitIndex) -> bool {
        let status = u8::from(1) << (bit as u8);
        self.status.bitand(status) == 0
    }
```
