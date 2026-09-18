### Title
Permanent freezing of pool creator fees when the fixed creator token account owner is blacklisted by the token mint - (File: programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs, programs/cp-swap/src/instructions/collect_creator_fee.rs)

### Summary
Both `collect_creator_fee` and `collect_creator_fee_permissionless` transfer accrued `creator_fees_token_0`/`creator_fees_token_1` from the pool vaults to token accounts whose owner is hard-coded to `pool_state.pool_creator`. If the mint (e.g. a Token-2022 mint with a `PermanentDelegate`/`DefaultAccountState`/transfer-hook-based blacklist extension, or any blacklist-capable token) blacklists that fixed creator address, the CPI transfer will revert on every call, forever, with no fallback path — permanently freezing the creator's accrued fee funds inside the pool vault, analogous to the report's stuck-bid/stuck-remainder scenario caused by a forced transfer to a fixed, non-substitutable address.

### Finding Description
`collect_creator_fee_permissionless` constrains the destination accounts to ATAs owned by the immutable `creator` account, which is itself constrained to `pool_state.load()?.pool_creator`: [1](#0-0) [2](#0-1) 

The actual transfer is executed unconditionally via `transfer_from_pool_vault_to_user`, with no try/catch or alternate-recipient fallback: [3](#0-2) 

`collect_creator_fee` (the permissioned variant, presumably callable by the creator or an authorized signer) follows the identical pattern, also transferring to a token account fixed to the creator: [4](#0-3) 

`transfer_from_pool_vault_to_user` is a thin wrapper around `token_2022::transfer_checked` and propagates any CPI error, including a blacklist/frozen-account rejection at the token-program level: [5](#0-4) 

Once `pool_state.pool_creator` (the account, or the derived ATA owner) is blacklisted by the token mint, every call to either collection instruction will revert at the `transfer_checked` CPI step, because the destination is fixed to that blacklisted owner and cannot be redirected. There is no admin or creator override to designate an alternate receiving address, and the accumulated `creator_fees_token_0`/`creator_fees_token_1` counters are only zeroed after a successful transfer, so the fees remain permanently trapped in the vault.

### Impact Explanation
This causes permanent freezing of the pool creator's accrued fee funds (real economic value sitting in the on-chain vault) with no recovery mechanism, matching the "permanent freezing of user funds" criterion. Unlike swap/withdraw/deposit, where the caller freely chooses their own destination token account (so a blacklist only self-DOSes the blacklisted party's own transaction), here the destination is protocol-fixed to `pool_creator`, so a single external blacklisting event by the token issuer permanently and irrecoverably locks the creator's fee accrual inside the pool, with no way for the creator (or anyone) to ever retrieve it.

### Likelihood Explanation
Requires the specific mint used by the pool to support a blacklist/freeze mechanism (e.g., Token-2022 extensions or a similar denylist token) and for the `pool_creator` address to become blacklisted after fees have begun accruing — a realistic scenario for any pool created with a compliance-controlled or extension-enabled mint, consistent with the audit's in-scope assumption that blacklistable tokens are supported.

### Recommendation
Wrap the `transfer_from_pool_vault_to_user` calls in `collect_creator_fee`/`collect_creator_fee_permissionless` in error-tolerant handling (e.g., only zero out the specific token's fee counter on successful transfer, leaving the other token's fee collectible independently), and/or allow the pool creator (or a privileged fallback) to redirect fee collection to an alternate, non-blacklisted token account instead of hard-binding to the original `pool_creator` ATA.

### Proof of Concept
1. Create a pool with `initialize`/`initialize_with_permission` using a Token-2022 mint that supports account freezing/blacklisting, with `payer` as `pool_creator`.
2. Perform swaps so that `creator_fees_token_0`/`creator_fees_token_1` accrue in `pool_state`.
3. Have the mint's freeze/blacklist authority blacklist the `pool_creator` address (or its ATA).
4. Call `collect_creator_fee_permissionless` (permissionless, callable by any attacker-chosen `payer`) — the `transfer_checked` CPI to `creator_token_0`/`creator_token_1` (owned by the blacklisted `creator`) reverts.
5. Every subsequent call to `collect_creator_fee`/`collect_creator_fee_permissionless` reverts identically; `creator_fees_token_0`/`creator_fees_token_1` remain non-zero and the underlying vault balance is permanently unclaimable, with no code path to redirect or recover it.

### Citations

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L17-20)
```rust
    /// The pool creator that receives the collected creator fees
    /// CHECK: the address is constrained to the `pool_creator` recorded in `pool_state`
    #[account(address = pool_state.load()?.pool_creator)]
    pub creator: UncheckedAccount<'info>,
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

**File:** programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs (L103-123)
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
