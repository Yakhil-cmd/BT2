### Title
Missing Transfer-Hook extra-account handling in token CPI wrappers can permanently freeze pool/LP funds - (File: programs/cp-swap/src/utils/token.rs)

### Summary
`transfer_from_user_to_pool_vault` and `transfer_from_pool_vault_to_user` invoke `token_2022::transfer_checked` with only `{from, to, authority, mint}` accounts and no mechanism to append the extra accounts a Token-2022 `TransferHook` extension requires. [1](#0-0) [2](#0-1) 

### Finding Description
Every user-facing instruction that moves tokens in or out of the pool vaults (`initialize`/`initialize_with_permission` deposits, `deposit`, `withdraw`, `swap_base_input`, `swap_base_output`, creator-fee collection) ultimately calls `transfer_from_user_to_pool_vault` / `transfer_from_pool_vault_to_user`, which forward directly to `anchor_spl::token_2022::transfer_checked`. [3](#0-2) 

Token-2022's `TransferHook` extension requires the caller to resolve and append the hook program's `ExtraAccountMetaList`-derived accounts to the instruction's account list (and to `remaining_accounts` on the CPI) before invoking `TransferChecked`; otherwise the SPL Token-2022 program itself rejects the transfer for hook-enabled mints because the hook program cannot be invoked with the missing accounts. The wrappers here build a fixed 4-account `TransferChecked` CPI context with no `remaining_accounts`/extra-account resolution path at all — unlike Orca's V2 CPI pattern referenced in the source report, which at least has a `remaining_accounts_info` field (even though it was hardcoded to `None`), this codebase has no such field or account-passing mechanism whatsoever.

The mint gating logic (`is_supported_mint`, referenced in `initialize.rs`) determines which Token-2022 extensions are permitted for pool creation, but was not retrievable in full during this review, so it is not verified with certainty whether `TransferHook` mints are explicitly rejected at pool-creation time. [4](#0-3) 

If a `TransferHook`-enabled mint is accepted (or if a mint enables the hook after pool creation, which Token-2022 extensions can permit for mutable configurations), any subsequent `transfer_checked` call from/to that mint's vault will fail on-chain because the required extra accounts are never supplied, blocking `deposit`, `withdraw`, and both swap directions for that pool.

### Impact Explanation
If reachable (i.e., if `is_supported_mint` does not exclude `TransferHook`, or a hook is enabled post-creation), this would permanently freeze all LP and swap funds in the affected pool: depositors could not add liquidity, LPs could not withdraw, and swaps involving the hook-enabled token would revert — with no code path to append the necessary accounts. This matches the "permanent freezing of user or LP funds" class from the reference report.

### Likelihood Explanation
Likelihood is **uncertain** without confirming the exact extension whitelist enforced by `is_supported_mint`. The token CPI wrappers themselves provide no mechanism for extra-account resolution regardless of what the whitelist permits, so the structural weakness exists; whether it is currently reachable via `initialize`/`initialize_with_permission` depends on gating logic not fully retrieved in this pass.

### Recommendation
1. In `programs/cp-swap/src/utils/token.rs`, extend `transfer_from_user_to_pool_vault` / `transfer_from_pool_vault_to_user` to detect `TransferHook` on the mint and resolve/append the required extra accounts via `spl_transfer_hook_interface::onchain::add_extra_account_metas_for_execute` (or equivalent), passing them through `ctx.remaining_accounts` from the calling instructions (`initialize`, `deposit`, `withdraw`, `swap_base_input`, `swap_base_output`).
2. Alternatively, explicitly confirm/enforce in `is_supported_mint` that mints with the `TransferHook` extension are rejected at `initialize`/`initialize_with_permission` time, closing the gap entirely rather than attempting to support it.

### Proof of Concept
Not independently reproduced in this review — full contents of the `is_supported_mint` whitelist function could not be retrieved to confirm whether `TransferHook`-extension mints currently pass validation at `initialize`/`initialize_with_permission`. A Devin session with full repository access is recommended to inspect `is_supported_mint` and confirm exploitability end-to-end (e.g., write a test that creates a pool with a `TransferHook`-enabled Token-2022 mint and attempts `deposit`/`withdraw`/`swap`).

### Citations

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

**File:** programs/cp-swap/src/instructions/initialize.rs (L253-271)
```rust
    transfer_from_user_to_pool_vault(
        ctx.accounts.creator.to_account_info(),
        ctx.accounts.creator_token_0.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.token_0_mint.to_account_info(),
        ctx.accounts.token_0_program.to_account_info(),
        init_amount_0,
        ctx.accounts.token_0_mint.decimals,
    )?;

    transfer_from_user_to_pool_vault(
        ctx.accounts.creator.to_account_info(),
        ctx.accounts.creator_token_1.to_account_info(),
        ctx.accounts.token_1_vault.to_account_info(),
        ctx.accounts.token_1_mint.to_account_info(),
        ctx.accounts.token_1_program.to_account_info(),
        init_amount_1,
        ctx.accounts.token_1_mint.decimals,
    )?;
```
