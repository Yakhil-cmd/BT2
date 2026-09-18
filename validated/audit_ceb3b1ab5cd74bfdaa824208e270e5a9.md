### Title
Interactions before effects in `collect_creator_fee` / `collect_creator_fee_permissionless` violate Checks-Effects-Interactions - (File: programs/cp-swap/src/instructions/collect_creator_fee.rs, programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs)

### Summary
Both `collect_creator_fee` and `collect_creator_fee_permissionless` perform the outbound token CPI transfers (`transfer_from_pool_vault_to_user`) before zeroing out `pool_state.creator_fees_token_0` / `creator_fees_token_1`, mirroring the pattern flagged in the referenced MCDEX audit finding where collateral was moved before state/effects were updated.

### Finding Description
In `collect_creator_fee`, the function reads `creator_fees_token_0`/`creator_fees_token_1` from `pool_state`, then immediately issues two `transfer_from_pool_vault_to_user` CPIs, and only afterward sets `pool_state.creator_fees_token_0 = 0; pool_state.creator_fees_token_1 = 0;`. [1](#0-0) 

The identical ordering occurs in `collect_creator_fee_permissionless`. [2](#0-1) 

The same pattern (interaction, i.e. CPI, before the corresponding bookkeeping effect) also exists in `collect_protocol_fee`, where fee counters are decremented before the loaded `pool_state` reference is dropped and the transfers are made — though there the state decrement happens before the CPI within a scoped block. [3](#0-2) 

The underlying transfer helper simply issues a `transfer_checked` CPI into the token program specified by the caller-supplied `token_0_program`/`token_1_program` accounts. [4](#0-3) 

### Impact Explanation
On Solana/Anchor, unlike EVM, a plain SPL Token or Token-2022 `transfer_checked` CPI does not hand control back to attacker-controlled code within the same instruction unless the mint carries a Token-2022 `TransferHook` extension that invokes an external program during the transfer. I was not able to confirm from the available code whether `initialize`/`initialize_with_permission` explicitly whitelist or reject mints carrying the `TransferHook` extension — the mint account constraints in `initialize.rs` only enforce `token_0_mint.key() < token_1_mint.key()` and correct `token_program` ownership, with no visible extension-type filtering in the files I could inspect. If unsupported/hostile extensions (like transfer hooks) are not filtered out at pool-creation time, a pool could in principle be created with such a mint, and the interaction-before-effect ordering in `collect_creator_fee`/`collect_creator_fee_permissionless` would let a hook re-enter the same instruction (via a different transaction/CPI path back into the program) and read/act on the stale (non-zeroed) `creator_fees_token_0/1` before it is cleared, or race with `swap_base_input`'s own fee-accrual which happens before this collect writes zero, though a full re-entrant double-collect requires the second call to be running with the still-stale fee amount, which is difficult to achieve safely within a single Solana transaction's CPI depth and account-lock rules. [1](#0-0) 

### Likelihood Explanation
Low-to-speculative. Solana's account-locking model and the requirement that all accounts be declared up front in a single instruction make classical reentrancy (as described in the EVM-based MCDEX report) much harder to realize than in Solidity. I could not verify within the indexed files whether the pool's mint-extension validation explicitly disallows `TransferHook`-enabled mints, which is the one realistic vector for CPI-triggered callbacks in this codebase; without that confirmation, this analog cannot be escalated to a confirmed exploitable path.

### Recommendation
Reorder both `collect_creator_fee` and `collect_creator_fee_permissionless` to zero `pool_state.creator_fees_token_0`/`creator_fees_token_1` before issuing the `transfer_from_pool_vault_to_user` CPIs, following Checks-Effects-Interactions, so that even if a hostile mint extension triggers a callback during the transfer, the pool's internal fee ledger has already been updated and cannot be read/exploited in a stale state. Additionally, confirm (or add, if missing) an explicit rejection of mints carrying extensions capable of invoking external code (e.g., `TransferHook`) during `initialize`/`initialize_with_permission`.

### Proof of Concept
Not constructible with confidence from the indexed code: I could not verify whether `initialize.rs`/`initialize_with_permission.rs` filter out Token-2022 `TransferHook`-extension mints, which is the prerequisite for any CPI-triggered callback in this program. Without that mint validation confirmed absent, a concrete re-entrant PoC on `collect_creator_fee`/`collect_creator_fee_permissionless` cannot be demonstrated; the finding is limited to the code-ordering deviation from Checks-Effects-Interactions shown above.

### Citations

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L88-122)
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

    pool_state.creator_fees_token_0 = 0;
    pool_state.creator_fees_token_1 = 0;
    pool_state.recent_epoch = Clock::get()?.epoch;
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L91-127)
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
```

**File:** programs/cp-swap/src/instructions/admin/collect_protocol_fee.rs (L79-128)
```rust
    let amount_0: u64;
    let amount_1: u64;
    let auth_bump: u8;
    {
        let mut pool_state = ctx.accounts.pool_state.load_mut()?;

        amount_0 = amount_0_requested.min(pool_state.protocol_fees_token_0);
        amount_1 = amount_1_requested.min(pool_state.protocol_fees_token_1);

        pool_state.protocol_fees_token_0 = pool_state
            .protocol_fees_token_0
            .checked_sub(amount_0)
            .unwrap();
        pool_state.protocol_fees_token_1 = pool_state
            .protocol_fees_token_1
            .checked_sub(amount_1)
            .unwrap();

        auth_bump = pool_state.auth_bump;
        pool_state.recent_epoch = Clock::get()?.epoch;
    }
    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.recipient_token_0_account.to_account_info(),
        ctx.accounts.vault_0_mint.to_account_info(),
        if ctx.accounts.vault_0_mint.to_account_info().owner == ctx.accounts.token_program.key {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        },
        amount_0,
        ctx.accounts.vault_0_mint.decimals,
        &[&[crate::AUTH_SEED.as_bytes(), &[auth_bump]]],
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_1_vault.to_account_info(),
        ctx.accounts.recipient_token_1_account.to_account_info(),
        ctx.accounts.vault_1_mint.to_account_info(),
        if ctx.accounts.vault_1_mint.to_account_info().owner == ctx.accounts.token_program.key {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        },
        amount_1,
        ctx.accounts.vault_1_mint.decimals,
        &[&[crate::AUTH_SEED.as_bytes(), &[auth_bump]]],
    )?;
```

**File:** programs/cp-swap/src/utils/token.rs (L17-42)
```rust
pub fn transfer_from_user_to_pool_vault<'a>(
    authority: AccountInfo<'a>,
    from: AccountInfo<'a>,
    to_vault: AccountInfo<'a>,
    mint: AccountInfo<'a>,
    token_program: AccountInfo<'a>,
    amount: u64,
    mint_decimals: u8,
) -> Result<()> {
    if amount == 0 {
        return Ok(());
    }
    token_2022::transfer_checked(
        CpiContext::new(
            *token_program.key,
            token_2022::TransferChecked {
                from,
                to: to_vault,
                authority,
                mint,
            },
        ),
        amount,
        mint_decimals,
    )
}
```
