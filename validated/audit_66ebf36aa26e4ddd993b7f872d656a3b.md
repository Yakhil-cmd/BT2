## Title
Pool accepts tokens with a freeze authority, allowing permanent freezing of LP/user funds in vaults - (File: `programs/cp-swap/src/utils/token.rs`)

## Summary
`raydium-cp-swap` never checks whether a token mint has a freeze authority before allowing it into a pool via `initialize`/`initialize_with_permission`. If the mint's freeze authority (or its Token-2022 equivalent) freezes the pool's vault token account after liquidity has been deposited, `deposit`, `withdraw`, `swap_base_input`, `swap_base_output`, and the creator-fee collectors all become permanently unusable for that pool, locking every depositor's funds inside the vault with no on-chain recovery path.

## Finding Description
`is_supported_mint` in `programs/cp-swap/src/utils/token.rs` is the sole gatekeeper used by `initialize` and `initialize_with_permission` to decide whether a mint may be used in a pool: [1](#0-0) 

For a legacy SPL Token mint (`*mint_info.owner == Token::id()`), the function returns `Ok(true)` unconditionally, with no inspection of the mint's `freeze_authority` field. For Token-2022 mints, the function only inspects the extension *type list* (allowing `TransferFeeConfig`, `MetadataPointer`, `TokenMetadata`, `InterestBearingConfig`, `ScaledUiAmount`) and likewise never checks `freeze_authority`.

`initialize` and `initialize_with_permission` call this check and then create the pool's token vaults and transfer initial liquidity into them: [2](#0-1) 

After the pool exists, `deposit`, `withdraw`, `swap_base_input`, `swap_base_output`, `collect_creator_fee`, and `collect_creator_fee_permissionless` all move tokens into/out of the same vault accounts via `transfer_checked` (through `transfer_from_user_to_pool_vault` / `transfer_from_pool_vault_to_user` in `programs/cp-swap/src/utils/token.rs`): [3](#0-2) 

None of these instructions, nor the account constraints on `token_0_vault`/`token_1_vault`, verify that the vault accounts remain unfrozen. If the holder of the mint's freeze authority calls the SPL Token/Token-2022 `FreezeAccount` instruction on either pool vault, every subsequent CPI `transfer_checked` against that vault will fail at the token-program level, causing `deposit`, `withdraw`, `swap_base_input`, `swap_base_output`, `collect_creator_fee`, and `collect_creator_fee_permissionless` to revert unconditionally for that pool. There is no admin or user-callable instruction in this program to remove/replace a frozen vault or migrate liquidity out, so all LP positions and pending creator fees tied to that pool are permanently stuck.

This mirrors the reported bug class where a pausable/freezable external asset (an NFT contract that can be paused by its owner) causes funds already committed to a smart contract to become permanently inaccessible, because the accepting contract performs no validation against that risk before or during custody of the asset.

## Impact Explanation
Any pool created (permissionlessly via `initialize`, or via `initialize_with_permission`) with a mint that retains a freeze authority is exposed: once the freeze authority freezes a vault token account, all LPs' deposited principal in that pool, and any accrued but uncollected creator fees, become permanently frozen with no recovery mechanism in the program. This is a permanent freezing of user/LP funds, matching a Medium/High severity impact.

## Likelihood Explanation
Likelihood is moderate: it requires a pool to be created with a mint that has a non-null freeze authority (common for many SPL tokens, especially newly launched or "rug-capable" tokens) and that authority to later exercise `FreezeAccount` on the vault. Because `is_supported_mint` performs no freeze-authority check at all, this is trivially reachable by simply creating/using a pool with such a token — no privileged access to the swap program itself is required, only control of the token's own freeze authority, which is analogous to the external NFT-pause actor in the reported bug class.

## Recommendation
Extend `is_supported_mint` (and the equivalent check in `initialize_with_permission`) to reject mints whose `freeze_authority` is set to `Some(_)` (for both legacy SPL Token and Token-2022 mints), unless explicitly whitelisted via `SupportMintAssociated`. Consider also periodically or defensively checking vault freeze state, and/or add an emergency withdrawal path that does not depend on a frozen vault (e.g., allow migrating remaining unfrozen-vault liquidity, or halting only the affected side).

## Proof of Concept
1. Attacker (or an ordinary user) creates a normal SPL-Token mint `M` and retains its freeze authority.
2. Call `initialize` with `token_0_mint = M`; `is_supported_mint` returns `Ok(true)` immediately since `*mint_info.owner == Token::id()`, so pool creation succeeds and `token_0_vault` is created and funded. [4](#0-3) 
3. One or more LPs call `deposit` to add liquidity of `M` into `token_0_vault`.
4. The freeze authority of `M` calls the SPL Token program's `FreezeAccount` instruction on `token_0_vault`.
5. Any subsequent call to `withdraw`, `swap_base_input`, `swap_base_output`, `collect_creator_fee`, or `collect_creator_fee_permissionless` involving this pool fails at the `transfer_checked` CPI because the vault account is frozen, permanently locking all deposited `M` tokens (and the paired token) in the vault with no recovery instruction available in the program.

### Citations

**File:** programs/cp-swap/src/utils/token.rs (L17-71)
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
