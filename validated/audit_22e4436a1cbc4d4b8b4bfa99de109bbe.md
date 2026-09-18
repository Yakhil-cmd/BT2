### Title
Coupled token_0/token_1 fee transfers in `collect_creator_fee` / `collect_creator_fee_permissionless` cause permanent freezing of a pool creator's fees if either token account becomes frozen/blacklisted - ([File: programs/cp-swap/src/instructions/collect_creator_fee.rs], [File: programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs])

### Summary
`collect_creator_fee` and its permissionless variant `collect_creator_fee_permissionless` atomically transfer both `creator_fees_token_0` and `creator_fees_token_1` in a single instruction, and only zero the accumulated fee counters after **both** transfers succeed. If the pool creator's destination token account for either mint becomes frozen (e.g. a USDC/Token-2022 account frozen by the mint's freeze authority for compliance/blacklist reasons), every future call to these instructions reverts, permanently locking the creator's accrued fees for **both** tokens, even though only one of the two token legs is affected.

### Finding Description
`collect_creator_fee` performs two sequential CPI transfers from the pool vaults to the creator's associated token accounts, and resets the fee counters only at the end: [1](#0-0) 

The permissionless variant, callable by any unprivileged signer (`payer`) on behalf of a fixed `creator` recorded in `pool_state`, has the identical atomic two-transfer structure: [2](#0-1) 

Both instructions call `transfer_from_pool_vault_to_user`, which performs a standard `transfer_checked` CPI that will fail if the destination token account is frozen: [3](#0-2) 

Because Anchor instructions are atomic, if the second transfer (say, `token_1`) reverts due to the destination account being frozen/blacklisted by the token issuer's freeze authority, the entire transaction rolls back — including the first, otherwise-successful `token_0` transfer — and `pool_state.creator_fees_token_0`/`creator_fees_token_1` are never reset. Since a token account frozen by a mint's freeze authority cannot be thawed by the account owner, every subsequent attempt to call `collect_creator_fee` or `collect_creator_fee_permissionless` will fail in the same way, permanently freezing the creator's entire accumulated fee balance for both tokens, not just the one whose account was frozen.

This mirrors the reported bug class: bundling multiple token transfers to different (or differently-controlled) destinations into one all-or-nothing operation means a single blacklisted/frozen recipient blocks recovery of unrelated funds.

### Impact Explanation
The pool creator's accumulated fees for both `token_0` and `token_1` become permanently unrecoverable once either destination token account is frozen. Since `creator_fees_token_0`/`creator_fees_token_1` continue to accrue with every swap (fees are added to these counters elsewhere in the swap logic) but can never be zeroed/withdrawn, the funds sitting in the pool vaults that are earmarked for the creator are permanently locked. This is a real loss of user funds (the pool creator), triggerable by an external, uncontrollable event (freeze/blacklist action from a token issuer such as USDC), consistent with a High-severity freezing-of-funds vulnerability.

### Likelihood Explanation
`collect_creator_fee_permissionless` can be triggered by *any* unprivileged account at any time — no special privileges are required to trigger the failing state; only the creator's frozen destination account matters, which is entirely outside program control. Given that Raydium CP Swap explicitly supports Token-2022 mints (which can include freezable/blacklist-capable tokens) as evidenced by the `token_program`/`token_program_2022` dual-path handling in `withdraw.rs`/`collect_creator_fee*.rs`, this scenario is realistic and requires no special conditions beyond one of the pool's two mints having freeze capability and the creator's account being frozen.

### Recommendation
Decouple the two fee transfers so that a failure in one does not block or roll back the other. Concretely:
1. Track and reset `creator_fees_token_0` and `creator_fees_token_1` independently, right after each individual transfer succeeds, rather than resetting both only after both transfers complete.
2. Optionally split `collect_creator_fee`/`collect_creator_fee_permissionless` into per-token instructions, or wrap each transfer so that a failure on one token still allows the other token's fee to be collected and its counter zeroed.
3. Consider allowing the creator to designate an alternate receiving account (similar to the original report's recommendation) so that a frozen/blacklisted primary account does not indefinitely block fee collection.

### Proof of Concept
1. Create a pool with `token_0` = a Token-2022 mint with freeze authority (or a similarly freezable SPL token), `token_1` = any other token.
2. Perform swaps so that `pool_state.creator_fees_token_0` and `creator_fees_token_1` both accumulate non-zero amounts (see accounting in `collect_creator_fee.rs` lines 90-94: [4](#0-3) ).
3. Have the mint's freeze authority freeze the creator's associated token account for `token_0` (simulating a blacklist action).
4. Call `collect_creator_fee_permissionless` (or `collect_creator_fee`) as any signer. The first `transfer_from_pool_vault_to_user` call for `token_0` reverts inside `token_2022::transfer_checked` because the destination account is frozen: [5](#0-4) .
5. Because Anchor rolls back the whole instruction on error, `creator_fees_token_1` is never transferred nor zeroed either, and every future call fails identically — the creator's fees for both tokens are permanently stuck in the vaults.

### Citations

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L88-94)
```rust
pub fn collect_creator_fee(ctx: Context<CollectCreatorFee>) -> Result<()> {
    let mut pool_state = ctx.accounts.pool_state.load_mut()?;
    let creator_fees_token_0 = pool_state.creator_fees_token_0;
    let creator_fees_token_1 = pool_state.creator_fees_token_1;
    if creator_fees_token_0 == 0 && creator_fees_token_1 == 0 {
        return err!(ErrorCode::NoFeeCollect);
    }
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L98-122)
```rust
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

    pool_state.creator_fees_token_0 = 0;
    pool_state.creator_fees_token_1 = 0;
    pool_state.recent_epoch = Clock::get()?.epoch;
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L91-129)
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

    pool_state.creator_fees_token_0 = 0;
    pool_state.creator_fees_token_1 = 0;
    pool_state.recent_epoch = Clock::get()?.epoch;

    Ok(())
```

**File:** programs/cp-swap/src/utils/token.rs (L44-71)
```rust
pub fn transfer_from_pool_vault_to_user<'a>(
    authority: AccountInfo<'a>,
    from_vault: AccountInfo<'a>,
    to: AccountInfo<'a>,
    mint: AccountInfo<'a>,
    token_program: AccountInfo<'a>,
    amount: u64,
    mint_decimals: u8,
    signer_seeds: &[&[&[u8]]],
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    token_2022::transfer_checked(
        CpiContext::new_with_signer(
            *token_program.key,
            token_2022::TransferChecked {
                from: from_vault,
                to,
                authority,
                mint,
            },
            signer_seeds,
        ),
        amount,
        mint_decimals,
    )
}
```
