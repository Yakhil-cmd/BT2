Confirmed: both `collect_creator_fee` and `collect_creator_fee_permissionless` fix the recipient to the canonical Associated Token Account of the pool creator (`associated_token::authority = creator`), with no ability to choose an alternate destination. This is a valid analog to the report.

### Title
Pool creator permanently loses accumulated creator fees if their canonical ATA for token_0 or token_1 becomes frozen/blacklisted - (File: `programs/cp-swap/src/instructions/collect_creator_fee.rs`, `programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs`)

### Summary
`collect_creator_fee` and `collect_creator_fee_permissionless` transfer both accumulated `creator_fees_token_0` and `creator_fees_token_1` to the pool creator's canonical Associated Token Accounts (ATAs) in a single instruction. The destination accounts are hard-constrained via `associated_token::authority = creator` and cannot be substituted with any alternate account. If either mint is a token with a freeze/blacklist authority (e.g. USDC) and the creator's specific ATA for that mint gets frozen, both fee transfers in the instruction revert, permanently locking the creator's accrued fees for both tokens with no recovery path.

### Finding Description
In `collect_creator_fee`, the recipient accounts are declared as: [1](#0-0) 

and in the permissionless variant identically constrained to the creator's canonical ATA: [2](#0-1) 

Both instructions execute two `transfer_from_pool_vault_to_user` CPIs unconditionally in the same call, resetting `creator_fees_token_0`/`creator_fees_token_1` to zero only if both succeed: [3](#0-2) 

`transfer_from_pool_vault_to_user` performs an SPL `transfer_checked` CPI which, for tokens with a freeze authority such as USDC, fails outright if either the source or destination token account is frozen: [4](#0-3) 

Because the recipient ATA address is deterministic (derived from `creator` pubkey + mint) and there is no constraint allowing the caller to specify an alternate destination account, once that specific ATA is frozen by the token issuer, every future call to either `collect_creator_fee` or `collect_creator_fee_permissionless` reverts on the frozen leg — and since both transfers occur in the same instruction and the fee counters are only cleared after both succeed, the creator also cannot recover the fees accrued in the *other*, unaffected token.

### Impact Explanation
This results in permanent freezing of the pool creator's LP/protocol-share funds (`creator_fees_token_0` and `creator_fees_token_1`) accrued in the pool. Both tokens' worth of fees become permanently unclaimable, not just the frozen one, since the instruction is atomic and the state is only updated on full success. This matches the accepted impact criteria of permanent freezing of user funds.

### Likelihood Explanation
Likelihood is moderate: it requires one of the pool's two mints to have a centralized freeze/blacklist authority (e.g., USDC, USDT) and the creator's specific token account to become frozen — a realistic scenario for pools paired with regulated stablecoins, and entirely outside the pool creator's control once it happens.

### Proof of Concept
1. A pool is created with `token_0 = USDC` and `token_1 = SOL_WRAPPED`, with `creator` set to address C.
2. The pool creator (C) accrues `creator_fees_token_0` (USDC) and `creator_fees_token_1` via swaps over time.
3. USDC issuer freezes C's canonical USDC ATA (the exact account derived by `associated_token::authority = creator, associated_token::mint = vault_0_mint`), e.g., due to a compliance action unrelated to this protocol.
4. C (or anyone, via the permissionless variant) calls `collect_creator_fee`/`collect_creator_fee_permissionless`. The `transfer_checked` CPI for `token_0` reverts because the destination ATA is frozen.
5. Because both transfers happen in one atomic instruction and `creator_fees_token_0`/`creator_fees_token_1` are only zeroed after both succeed, the call always reverts, and C can never withdraw the token_1 fees either, despite that token account being perfectly healthy.

### Citations

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L58-76)
```rust
    /// The address that receives the collected token_0 fund fees
    #[account(
        init_if_needed,
        associated_token::mint = vault_0_mint,
        associated_token::authority = creator,
        payer = creator,
        associated_token::token_program = token_0_program,
    )]
    pub creator_token_0: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The address that receives the collected token_1 fund fees
    #[account(
        init_if_needed,
        associated_token::mint = vault_1_mint,
        associated_token::authority = creator,
        payer = creator,
        associated_token::token_program = token_1_program,
    )]
    pub creator_token_1: Box<InterfaceAccount<'info, TokenAccount>>,
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee.rs (L88-125)
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

    Ok(())
}
```

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L61-79)
```rust
    /// The address that receives the collected token_0 creator fees
    #[account(
        init_if_needed,
        associated_token::mint = vault_0_mint,
        associated_token::authority = creator,
        payer = payer,
        associated_token::token_program = token_0_program,
    )]
    pub creator_token_0: Box<InterfaceAccount<'info, TokenAccount>>,

    /// The address that receives the collected token_1 creator fees
    #[account(
        init_if_needed,
        associated_token::mint = vault_1_mint,
        associated_token::authority = creator,
        payer = payer,
        associated_token::token_program = token_1_program,
    )]
    pub creator_token_1: Box<InterfaceAccount<'info, TokenAccount>>,
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
