### Title
Withdrawal from a pool can be permanently blocked by a freezable (or otherwise transfer-restricted) legacy SPL Token used as a pool asset, trapping LP funds - (File: `programs/cp-swap/src/instructions/withdraw.rs`, `programs/cp-swap/src/utils/token.rs`)

### Summary
The `is_supported_mint` check that gates pool creation only inspects Token-2022 extensions and unconditionally accepts any legacy SPL Token mint, without checking for a freeze authority. Since `withdraw` requires both token transfers (token_0 and token_1) to succeed atomically, a token with an active freeze authority that freezes the pool's vault account can permanently block all LP withdrawals from that pool, mirroring the "rebalance blocked by paused tokens" bug class from the referenced report (an externally-controlled transfer-halting mechanism on one asset stalls a core protocol function that must move both assets together).

### Finding Description
`is_supported_mint` in `programs/cp-swap/src/utils/token.rs` is used by both `initialize` and `initialize_with_permission` to gate which mints are allowed to be paired in a new pool: [1](#0-0) 

For a legacy SPL Token mint (`Token::id()` owner), the function returns `Ok(true)` unconditionally with no check of the mint's freeze authority: [2](#0-1) 

`initialize`/`initialize_with_permission` invoke this check before creating the pool and vaults but perform no additional freeze-authority validation: [3](#0-2) [4](#0-3) 

The pool's `withdraw` instruction requires both vault-to-user transfers to succeed in the same transaction, with no per-token opt-out: [5](#0-4) 

`transfer_from_pool_vault_to_user` issues a `transfer_checked` CPI, which the SPL Token program will reject if the source (vault) or destination account is frozen: [6](#0-5) 

Because a pool creator can freely pair a legacy SPL Token mint retaining a freeze authority (nothing in `Initialize`'s account constraints validates mint authority/freeze authority of `token_0_mint`/`token_1_mint`), an attacker (acting as pool creator, or the mint's freeze authority holder) can:
1. Create a pool pairing a normal token with a token they control that has an active freeze authority.
2. Attract LP deposits.
3. Freeze the pool's vault token account for that mint using the freeze authority (a standard SPL Token instruction any freeze-authority holder can invoke off-chain/independently).
4. Because `withdraw` performs both transfers atomically and neither can be skipped nor substituted, every subsequent `withdraw` call will revert once the frozen vault's `transfer_checked` CPI fails, permanently trapping all LPs' funds in the pool (including the unrelated, non-frozen token side).

This is directly analogous to the referenced report: an externally controllable transfer-halting mechanism (there: `pause()`, here: SPL Token account `freeze`) on one of the two pool assets stalls an all-or-nothing operation that must move both assets, blocking it indefinitely.

### Impact Explanation
This results in permanent freezing of LP funds for any pool containing a token whose mint retains (or is granted) a freeze authority, since `withdraw` is strictly atomic across both assets and there is no partial-withdraw or single-asset emergency-withdraw path in scope. This satisfies the "permanent freezing of user or LP funds" criterion for a valid High-severity finding.

### Likelihood Explanation
Likelihood is high: pool creation is permissionless (`initialize`/`initialize_with_permission` can be called by any signer with `disable_create_pool` off), legacy SPL Token mints with freeze authorities are common and not filtered by `is_supported_mint`, and freezing an account is a single, freely available instruction to whoever holds the freeze authority — no privileged program access or off-chain assumptions beyond normal token mint administration are required.

### Recommendation
Extend `is_supported_mint` to reject legacy SPL Token mints (and Token-2022 mints) that have a non-null freeze authority, or require freeze authority to be renounced/verified as `None` before allowing a mint to be used as pool collateral. Additionally, consider providing an emergency/partial withdrawal path that does not require both token transfers to succeed atomically, so that LPs can still recover the unaffected asset if the counter-asset's vault becomes transfer-restricted.

### Proof of Concept
1. Attacker creates mint `M` (legacy SPL Token) with `freeze_authority = attacker`.
2. Attacker calls `initialize` (or `initialize_with_permission`) pairing `M` with a normal token `X`; `is_supported_mint` passes for both because `M` is owned by the legacy Token program (line 340-342 in `token.rs`).
3. Victim LPs deposit into the pool via `deposit`, receiving LP tokens.
4. Attacker calls the standard SPL Token `FreezeAccount` instruction against the pool's `token_0_vault` (or `token_1_vault`) holding `M`, using their freeze authority.
5. Any subsequent `withdraw` call by any LP fails: `transfer_from_pool_vault_to_user` for the frozen vault reverts inside the SPL Token program's `transfer_checked` CPI (`programs/cp-swap/src/utils/token.rs:44-71`), and because `withdraw` performs both transfers sequentially within one instruction (`programs/cp-swap/src/instructions/withdraw.rs:188-216`), the whole transaction reverts — LPs cannot withdraw either asset, permanently.

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

**File:** programs/cp-swap/src/instructions/initialize.rs (L196-200)
```rust
    if !(is_supported_mint(&ctx.accounts.token_0_mint, mint0_associated_is_initialized).unwrap()
        && is_supported_mint(&ctx.accounts.token_1_mint, mint1_associated_is_initialized).unwrap())
    {
        return err!(ErrorCode::NotSupportMint);
    }
```

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L208-212)
```rust
    if !(is_supported_mint(&ctx.accounts.token_0_mint, mint0_associated_is_initialized).unwrap()
        && is_supported_mint(&ctx.accounts.token_1_mint, mint1_associated_is_initialized).unwrap())
    {
        return err!(ErrorCode::NotSupportMint);
    }
```

**File:** programs/cp-swap/src/instructions/withdraw.rs (L188-216)
```rust
    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.token_0_account.to_account_info(),
        ctx.accounts.vault_0_mint.to_account_info(),
        if ctx.accounts.vault_0_mint.to_account_info().owner == ctx.accounts.token_program.key {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        },
        token_0_amount,
        ctx.accounts.vault_0_mint.decimals,
        &[&[crate::AUTH_SEED.as_bytes(), &[pool_state.auth_bump]]],
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_1_vault.to_account_info(),
        ctx.accounts.token_1_account.to_account_info(),
        ctx.accounts.vault_1_mint.to_account_info(),
        if ctx.accounts.vault_1_mint.to_account_info().owner == ctx.accounts.token_program.key {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        },
        token_1_amount,
        ctx.accounts.vault_1_mint.decimals,
        &[&[crate::AUTH_SEED.as_bytes(), &[pool_state.auth_bump]]],
    )?;
```
