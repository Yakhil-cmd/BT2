### Title
Malicious pool token with retained freeze authority can permanently disable withdrawals — ([File: programs/cp-swap/src/instructions/withdraw.rs])

### Summary
`withdraw()` atomically transfers both pool tokens back to the LP and reverts entirely if either transfer fails. Because pool creation is permissionless and `is_supported_mint` never rejects mints that retain a freeze authority, an attacker can create a pool with a malicious mint, wait for LPs to deposit, then freeze the relevant token account to permanently block `withdraw()` for all LPs, similar to the FactoryDAO M-02 pattern where one bad token in a set blocks retrieval of an otherwise-healthy deposit.

### Finding Description
Anyone can permissionlessly create a pool via `initialize`/`initialize_with_permission`, where `creator` is an arbitrary signer [1](#0-0) . The only mint validation performed is `is_supported_mint`, which whitelists a small set of Token-2022 extensions but returns `true` unconditionally for any legacy SPL Token mint, and does not inspect the mint's `freeze_authority` field at all: [2](#0-1) .

This means a pool creator can mint token_0 or token_1 as a normal SPL Token (or Token-2022 mint using only whitelisted extensions) while retaining the freeze authority for themselves. `withdraw()` then requires both `transfer_from_pool_vault_to_user` calls (token_0 and token_1) to succeed before the instruction completes, with the LP-burn happening first and being rolled back atomically if either transfer fails: [3](#0-2) . Both transfers use `transfer_checked` under Token/Token-2022 semantics: [4](#0-3) , which fails if the source vault or destination token account is frozen.

If the malicious pool creator freezes the pool's token vault (or a user's associated token account) for the mint they control, every subsequent `withdraw()` call for that pool reverts, and there is no `emergencyWithdraw`-style fallback that allows a user to at least reclaim the unaffected token or their principal.

### Impact Explanation
Once LPs deposit into such a pool, the attacker can freeze the malicious-mint vault and permanently trap both tokens (including the entirely healthy counterpart token) for every liquidity provider in the pool, since `withdraw()` is all-or-nothing. This is a permanent freezing of user/LP funds with no recovery instruction available in the current design.

### Likelihood Explanation
Pool creation is permissionless, so an attacker only needs to mint a token with freeze authority retained and pair it with a legitimate token to attract deposits (e.g., disguised as a normal new project token). This requires no special privilege beyond normal SPL Token mint creation and calling the already-public `initialize` instruction, matching the "malicious pool creator" pattern acknowledged in the original finding.

### Recommendation
- Reject mints that retain a non-null `freeze_authority` in `is_supported_mint`, or clearly document/flag such pools as high-risk before allowing deposits.
- Add an emergency/partial withdrawal path that lets LPs redeem the unaffected token (or burns LP tokens against only the transferable side) when one token transfer fails, rather than reverting the entire withdrawal atomically.

### Proof of Concept
1. Attacker creates SPL Token mint `M` with `freeze_authority = attacker`.
2. Attacker calls `initialize` pairing `M` with a reputable token, passing `is_supported_mint` checks since freeze authority isn't inspected [5](#0-4) .
3. Users deposit liquidity into the pool.
4. Attacker calls SPL Token `FreezeAccount` on the pool's `token_0_vault` (or a target LP's token account) for mint `M`.
5. Any subsequent `withdraw()` call fails inside `transfer_from_pool_vault_to_user` for the frozen side, reverting the whole instruction including the LP burn [6](#0-5) , permanently locking both tokens for the LP.

### Citations

**File:** programs/cp-swap/src/instructions/initialize.rs (L20-24)
```rust
#[derive(Accounts)]
pub struct Initialize<'info> {
    /// Address paying to create the pool. Can be anyone
    #[account(mut)]
    pub creator: Signer<'info>,
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

**File:** programs/cp-swap/src/instructions/withdraw.rs (L178-216)
```rust
    pool_state.lp_supply = pool_state.lp_supply.checked_sub(lp_token_amount).unwrap();
    token_burn(
        ctx.accounts.owner.to_account_info(),
        ctx.accounts.token_program.to_account_info(),
        ctx.accounts.lp_mint.to_account_info(),
        ctx.accounts.owner_lp_token.to_account_info(),
        lp_token_amount,
        &[&[crate::AUTH_SEED.as_bytes(), &[pool_state.auth_bump]]],
    )?;

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
