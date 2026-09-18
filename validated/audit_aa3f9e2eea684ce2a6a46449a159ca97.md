### Title
Malicious pool creator can permanently freeze accumulated creator fees by exploiting an unrestricted mint freeze authority - (File: `programs/cp-swap/src/instructions/collect_creator_fee.rs`, `programs/cp-swap/src/instructions/collect_creator_fee_permissionless.rs`)

### Summary
`collect_creator_fee` and `collect_creator_fee_permissionless` withdraw both `creator_fees_token_0` and `creator_fees_token_1` in a single instruction via two sequential `transfer_from_pool_vault_to_user` calls. If either transfer reverts, the whole instruction fails and neither token's accrued creator fees are collected or zeroed. A pool creator who controls the freeze authority of one of the pool's mints can create a pool, let creator fees accrue from real trading activity, then freeze their own creator-fee token account, permanently bricking both instructions the same way the referenced report's `withdrawTaxes()` could be permanently DoS'd by one malicious `transfer`.

### Finding Description
`is_supported_mint` in `programs/cp-swap/src/utils/token.rs` only whitelists specific Token-2022 *extension types* (`TransferFeeConfig`, `MetadataPointer`, `TokenMetadata`, `InterestBearingConfig`, `ScaledUiAmount`) and does not restrict or check the mint's base `freeze_authority` field at all: [1](#0-0) 

At `initialize`, the pool creator supplies `token_0_mint`/`token_1_mint` and is only constrained by `is_supported_mint`, `mint::token_program`, and `token_0_mint < token_1_mint`; nothing prevents the creator from using a mint for which they themselves hold the freeze authority: [2](#0-1) 

Both fee-collection paths pay out `creator_fees_token_0` and `creator_fees_token_1` to fixed, creator-owned associated token accounts in a single instruction, with no per-token collection option and no try/catch isolation between the two transfers: [3](#0-2) [4](#0-3) 

`transfer_from_pool_vault_to_user` performs a plain `transfer_checked` CPI, which the SPL/Token-2022 program will reject outright if the destination token account is frozen: [5](#0-4) 

Attack path:
1. Creator calls `initialize` using a mint (say `token_0_mint`) they created and for which they retained `freeze_authority` (base Mint field, unrelated to and unchecked by `is_supported_mint`).
2. Trading occurs; `creator_fees_token_0` and `creator_fees_token_1` accumulate in `pool_state` from real swappers' trades (see `PoolState.creator_fees_token_0/1`) [6](#0-5) .
3. Creator calls `collect_creator_fee_permissionless` (or `collect_creator_fee`) once to force `init_if_needed` creation of `creator_token_0`, the ATA that will receive token_0 creator fees.
4. Using their retained freeze authority over `token_0_mint`, the creator freezes `creator_token_0`.
5. Every subsequent call to `collect_creator_fee` or `collect_creator_fee_permissionless` now reverts on the `transfer_checked` into the frozen `creator_token_0`, because both transfers happen in one atomic instruction and the first (token_0) failure aborts the whole transaction — meaning `creator_fees_token_1`, funded by real trading activity, also can never be collected, exactly mirroring the referenced `withdrawTaxes()` "one bad token blocks all" defect.

### Impact Explanation
This permanently locks legitimate, trader-funded creator fee balances (`creator_fees_token_0`/`creator_fees_token_1`) inside the pool's vaults with no recovery path — neither `collect_creator_fee` (creator-authorized) nor `collect_creator_fee_permissionless` (anyone-callable) can ever succeed once one leg is frozen, since both always attempt both transfers atomically and there is no fallback/skip/try-catch logic. This is a permanent freezing of fee-derived funds, satisfying the Medium/High bar for permanent freezing of funds.

### Likelihood Explanation
The path only requires actions available to an unprivileged pool creator: choosing/creating a mint with a self-controlled freeze authority (unchecked by `is_supported_mint`) and later calling the standard SPL/Token-2022 `FreezeAccount` instruction on their own fee ATA. No special build flags, validator collusion, or off-chain components are needed — it is fully reachable from ordinary user-submitted transactions the creator already controls (`initialize`, `collect_creator_fee_permissionless`, and the token program's freeze instruction).

### Recommendation
- Collect and zero `creator_fees_token_0` and `creator_fees_token_1` independently (e.g., take a `token_index`/mask parameter or split into two instructions) so a failure on one token cannot block the other.
- Alternatively wrap each `transfer_from_pool_vault_to_user` call in isolated error handling that re-instates the corresponding `creator_fees_token_*` counter on failure instead of reverting the whole instruction.
- Consider validating/prohibiting mints whose freeze authority is the pool creator (or is otherwise attacker-controlled) for pools that accrue creator fees, similar to the existing extension-type allowlist in `is_supported_mint`.

### Proof of Concept
1. Attacker creates `token_0_mint` (SPL Token or Token-2022) with `freeze_authority` set to themselves.
2. Attacker calls `initialize` (`programs/cp-swap/src/instructions/initialize.rs`) creating a pool with this mint as `token_0_mint`.
3. Normal users swap through the pool; `creator_fees_token_0` and `creator_fees_token_1` accrue in `PoolState`.
4. Attacker calls `collect_creator_fee_permissionless` once to create `creator_token_0` ATA and collect the first round of fees.
5. Attacker issues a `FreezeAccount` instruction (signed with their freeze authority) against `creator_token_0`.
6. Any subsequent call to `collect_creator_fee` or `collect_creator_fee_permissionless` reverts inside `transfer_from_pool_vault_to_user` for `token_0_vault → creator_token_0`, aborting the whole instruction and leaving `creator_fees_token_1` (funded by other traders) permanently stuck alongside `creator_fees_token_0`.

### Citations

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

**File:** programs/cp-swap/src/utils/token.rs (L335-360)
```rust
pub fn is_supported_mint(
    mint_account: &InterfaceAccount<Mint>,
    mint_associated_is_initialized: bool,
) -> Result<bool> {
    let mint_info = mint_account.to_account_info();
    if *mint_info.owner == Token::id() {
        return Ok(true);
    }
    if mint_associated_is_initialized {
        return Ok(true);
    }
    let mint_data = mint_info.try_borrow_data()?;
    let mint = StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&mint_data)?;
    let extensions = mint.get_extension_types()?;
    for e in extensions {
        if e != ExtensionType::TransferFeeConfig
            && e != ExtensionType::MetadataPointer
            && e != ExtensionType::TokenMetadata
            && e != ExtensionType::InterestBearingConfig
            && e != ExtensionType::ScaledUiAmount
        {
            return Ok(false);
        }
    }
    Ok(true)
}
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L52-63)
```rust
    /// Token_0 mint, the key must smaller than token_1 mint.
    #[account(
        constraint = token_0_mint.key() < token_1_mint.key(),
        mint::token_program = token_0_program,
    )]
    pub token_0_mint: Box<InterfaceAccount<'info, Mint>>,

    /// Token_1 mint, the key must grater then token_0 mint.
    #[account(
        mint::token_program = token_1_program,
    )]
    pub token_1_mint: Box<InterfaceAccount<'info, Mint>>,
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

**File:** programs/cp-swap/src/states/pool.rs (L125-126)
```rust
    pub creator_fees_token_0: u64,
    pub creator_fees_token_1: u64,
```
