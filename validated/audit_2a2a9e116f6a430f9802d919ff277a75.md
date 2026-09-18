## Analysis

The reported bug class is: a token issuer can weaponize an admin-controlled compliance mechanism (freeze/blacklist) against a specific address to trap funds that are held in a shared contract-controlled account. The reachable analog in this Solana program is the missing freeze-authority check in `is_supported_mint`, which gates which mints can be paired in a pool.

### Title
Pools accept mints with an active Freeze Authority, allowing the mint issuer to permanently freeze the shared pool vault and lock all LPs' funds - (File: `programs/cp-swap/src/utils/token.rs`)

### Summary
`initialize` and `initialize_with_permission` validate token mints via `is_supported_mint`, which only inspects Token-2022 *extension types* (and unconditionally accepts any legacy SPL Token mint). Neither path checks whether the mint has a non-null `freeze_authority`. Because the pool's token vaults (`token_0_vault`/`token_1_vault`) are ordinary token accounts owned by the mint, the mint's freeze authority can call `FreezeAccount` on the vault at any time, after which every subsequent `transfer_checked` from that vault reverts.

### Finding Description
`is_supported_mint` immediately returns `Ok(true)` for any mint owned by the legacy `Token` program, and for Token-2022 mints only rejects mints carrying disallowed *extensions* (it never inspects the base `Mint.freeze_authority` field): [1](#0-0) 

This function gates pool creation in both `initialize`: [2](#0-1) 

and `initialize_with_permission`: [3](#0-2) 

The vaults created for the pool are standard token accounts owned by the pool `authority` PDA but are still subject to the mint's `freeze_authority`, which is an unrelated, external, mint-level admin key: [4](#0-3) 

All withdrawal-style transfers out of the vault (`withdraw`, `swap_base_input`/`swap_base_output`, `collect_creator_fee`, `collect_creator_fee_permissionless`, `collect_fund_fee`) route through `transfer_from_pool_vault_to_user`, which performs `token_2022::transfer_checked` with no fallback if the vault account is frozen: [5](#0-4) 

If the vault's `freeze_authority` freezes the vault token account (an action entirely outside the program's control, exactly analogous to a USDC-style blacklist action on an address), every one of these instructions will revert permanently for that pool, because unlike a single user's wallet, the vault is shared across all liquidity providers.

### Impact Explanation
Once a vault account is frozen, ALL of the following become permanently unusable for the pool: `deposit` and `withdraw` (LP funds), `swap_base_input`/`swap_base_output` (trader funds mid-flight and pool liquidity), and `collect_creator_fee`/`collect_creator_fee_permissionless`/`collect_fund_fee` (accrued fees). Because the vault is a single shared account for the whole pool, this is a permanent freeze of funds belonging to every LP and trader in that pool, not just the mint issuer's own counterparty — a stronger impact than the referenced report's single-account blacklist scenario. This satisfies "permanent freezing of user or LP funds."

### Likelihood Explanation
Pool creation via `initialize` is permissionless — `creator` is just a `Signer`, and pool creation via `initialize_with_permission` requires only a valid `create_permission_pda`, not privileged control of the protocol. An attacker can mint a legacy SPL Token (which is unconditionally accepted regardless of freeze authority) or a Token-2022 mint using only whitelisted extensions, retain the freeze authority, create a pool, wait for deposits/swaps, and then freeze the vault at will. No validator collusion, leaked keys, or non-default builds are required — a single attacker-controlled mint plus a standard `initialize` transaction suffices.

### Recommendation
In `is_supported_mint` (and equivalently for legacy SPL Token mints), explicitly reject mints whose `freeze_authority` is `Some(_)` (unless it is provably immutable/None, or the protocol intentionally allowlists specific freeze-authority-bearing mints such as USDC via governance). This closes the gap where legacy SPL Token mints bypass all extension checks and where Token-2022 mints are checked only for extension types, not the base freeze-authority field.

### Proof of Concept
1. Attacker creates an SPL Token (legacy `Token` program) mint `M` and keeps the freeze authority for themselves.
2. Attacker calls `initialize` (or `initialize_with_permission`) pairing `M` with e.g. USDC/WSOL; `is_supported_mint` returns `true` immediately because `mint_info.owner == Token::id()`, per `programs/cp-swap/src/utils/token.rs:340-342`.
3. Honest users `deposit` liquidity and/or perform `swap_base_input`/`swap_base_output` against the pool, populating `token_0_vault`/`token_1_vault`.
4. Attacker, using the mint's freeze authority, issues `FreezeAccount` against the pool's vault token account for mint `M` (a normal SPL Token instruction, requires no cooperation from the program).
5. All subsequent `withdraw`, `swap_base_input`/`swap_base_output`, `collect_creator_fee(_permissionless)`, and `collect_fund_fee` calls that touch the frozen vault fail at `transfer_checked` inside `transfer_from_pool_vault_to_user` (`programs/cp-swap/src/utils/token.rs:44-71`), permanently locking all depositors' and traders' funds in that pool.

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

**File:** programs/cp-swap/src/instructions/initialize.rs (L188-200)
```rust
    let mint0_associated_is_initialized = support_mint_associated_is_initialized(
        &ctx.remaining_accounts,
        &ctx.accounts.token_0_mint,
    )?;
    let mint1_associated_is_initialized = support_mint_associated_is_initialized(
        &ctx.remaining_accounts,
        &ctx.accounts.token_1_mint,
    )?;
    if !(is_supported_mint(&ctx.accounts.token_0_mint, mint0_associated_is_initialized).unwrap()
        && is_supported_mint(&ctx.accounts.token_1_mint, mint1_associated_is_initialized).unwrap())
    {
        return err!(ErrorCode::NotSupportMint);
    }
```

**File:** programs/cp-swap/src/instructions/initialize.rs (L209-238)
```rust
    // due to stack/heap limitations, we have to create redundant new accounts ourselves.
    create_token_account(
        &ctx.accounts.authority.to_account_info(),
        &ctx.accounts.creator.to_account_info(),
        &ctx.accounts.token_0_vault.to_account_info(),
        &ctx.accounts.token_0_mint.to_account_info(),
        &ctx.accounts.system_program.to_account_info(),
        &ctx.accounts.token_0_program.to_account_info(),
        &[
            POOL_VAULT_SEED.as_bytes(),
            ctx.accounts.pool_state.key().as_ref(),
            ctx.accounts.token_0_mint.key().as_ref(),
            &[ctx.bumps.token_0_vault][..],
        ],
    )?;

    create_token_account(
        &ctx.accounts.authority.to_account_info(),
        &ctx.accounts.creator.to_account_info(),
        &ctx.accounts.token_1_vault.to_account_info(),
        &ctx.accounts.token_1_mint.to_account_info(),
        &ctx.accounts.system_program.to_account_info(),
        &ctx.accounts.token_1_program.to_account_info(),
        &[
            POOL_VAULT_SEED.as_bytes(),
            ctx.accounts.pool_state.key().as_ref(),
            ctx.accounts.token_1_mint.key().as_ref(),
            &[ctx.bumps.token_1_vault][..],
        ],
    )?;
```

**File:** programs/cp-swap/src/instructions/initialize_with_permission.rs (L200-212)
```rust
    let mint0_associated_is_initialized = support_mint_associated_is_initialized(
        &ctx.remaining_accounts,
        &ctx.accounts.token_0_mint,
    )?;
    let mint1_associated_is_initialized = support_mint_associated_is_initialized(
        &ctx.remaining_accounts,
        &ctx.accounts.token_1_mint,
    )?;
    if !(is_supported_mint(&ctx.accounts.token_0_mint, mint0_associated_is_initialized).unwrap()
        && is_supported_mint(&ctx.accounts.token_1_mint, mint1_associated_is_initialized).unwrap())
    {
        return err!(ErrorCode::NotSupportMint);
    }
```
