## Title
Malicious Freezable SPL Token Mint Enables Permanent DoS of Withdraw/Swap, Trapping Paired LP Funds - (File: programs/cp-swap/src/utils/token.rs, programs/cp-swap/src/instructions/withdraw.rs)

### Summary
Pool creation (`initialize`/`initialize_with_permission`) accepts any legacy SPL Token mint without checking whether its freeze authority has been renounced. A malicious pool creator can pair such a mint with a legitimate token (e.g. USDC), attract deposits from unsuspecting LPs, then freeze the pool's vault token account for the malicious mint. Because `withdraw` and swap instructions perform per-instruction atomic transfers of both pool tokens with no fallback/pull mechanism, a frozen vault causes every subsequent withdraw/swap call for that pool to revert, permanently locking the paired legitimate token inside the pool.

### Finding Description
`is_supported_mint` in `programs/cp-swap/src/utils/token.rs` short-circuits to `Ok(true)` for any mint owned by the legacy `Token` program, without inspecting the mint's `freeze_authority`: [1](#0-0) 

This function is the sole mint-validity gate used during permissionless pool creation: [2](#0-1) 

There is no check anywhere in the on-chain program for `freeze_authority` or account-frozen state (the only occurrences of freeze-related logic are in client test helpers, not the program), so a mint that retains a live freeze authority is treated identically to a fully-trusted mint.

`withdraw` then unconditionally performs two token transfers for token_0 and token_1 in the same instruction, with no error handling to isolate a failure in one leg from the other: [3](#0-2) 

Both calls route through `transfer_from_pool_vault_to_user`, which is a plain `transfer_checked` CPI with no fallback for a reverting/frozen source account: [4](#0-3) 

The same push-only, all-or-nothing transfer pattern is used by `swap_base_input`/`swap_base_output` (transfer input then output) and by `collect_creator_fee`/`collect_creator_fee_permissionless` (transfer token_0 fee then token_1 fee), so a frozen vault for one side of the pool blocks withdrawals, swaps, and creator-fee collection for the entire pool. [5](#0-4) 

### Impact Explanation
Because the malicious pool creator controls the mint's freeze authority, they can freeze the pool's vault token account for their malicious mint at any time after legitimate LPs have deposited the paired legitimate token. Since `withdraw` (and swap) transfer both sides of the pool atomically in a single instruction, the frozen vault causes the CPI transfer to fail and the entire instruction to revert — there is no partial-withdraw or pull-based recovery path. This permanently traps the legitimate LP token (e.g. USDC) inside the pool alongside the worthless malicious token, a permanent freeze of user/LP funds, meeting the High severity bar per the validation rules.

### Likelihood Explanation
Pool creation via `initialize`/`initialize_with_permission` is permissionless/unprivileged — any user can create a pool pairing an arbitrary mint they control with a real, valuable token, and the only mint-safety gate (`is_supported_mint`) does not check freeze authority for legacy SPL tokens. An attacker only needs to: (1) create a Token mint with freeze authority retained, (2) initialize a pool with that mint paired to a legitimate token, (3) wait for/incentivize LP deposits, and (4) freeze the vault account for the malicious mint. This requires no special privileges beyond being the mint's freeze authority and pool creator, making the attack straightforward and reachable from a single attacker-controlled flow.

### Recommendation
Reject mints with a non-null `freeze_authority` (or require it to be explicitly `None`) during pool initialization for both `Token` and `Token-2022` programs. Additionally, consider decoupling the two-token transfer in `withdraw` so a stuck vault for one token does not block redemption of the other, or provide an escape-hatch/pull-based recovery mechanism (e.g., per-token withdrawal) so LPs are not permanently frozen out of a healthy token merely because the paired token's vault becomes non-transferable.

### Proof of Concept
1. Attacker creates a legacy SPL Token mint `M` and does not set `freeze_authority` to `None`, keeping it as the attacker's key.
2. Attacker calls `initialize` pairing `M` with a legitimate token `USDC`; `is_supported_mint` passes because `M` is owned by `Token::id()` (`programs/cp-swap/src/utils/token.rs` lines 335-345), with no freeze-authority check performed.
3. Legitimate LPs call `deposit`, contributing `USDC` and `M` into the pool vaults.
4. Attacker invokes `FreezeAccount` on the pool's `token_0_vault` (holding `M`) using their retained freeze authority.
5. Any subsequent `withdraw` call reverts at the `transfer_from_pool_vault_to_user` CPI for the frozen vault (`programs/cp-swap/src/instructions/withdraw.rs` lines 188-201), atomically failing the whole instruction and leaving LPs unable to ever redeem their `USDC` share, since the `USDC` transfer (lines 203-216) is never reached in a successful transaction.

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

**File:** programs/cp-swap/src/utils/token.rs (L335-345)
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

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L182-201)
```rust
    transfer_from_user_to_pool_vault(
        ctx.accounts.payer.to_account_info(),
        ctx.accounts.input_token_account.to_account_info(),
        ctx.accounts.input_vault.to_account_info(),
        ctx.accounts.input_token_mint.to_account_info(),
        ctx.accounts.input_token_program.to_account_info(),
        input_transfer_amount,
        ctx.accounts.input_token_mint.decimals,
    )?;

    transfer_from_pool_vault_to_user(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.output_vault.to_account_info(),
        ctx.accounts.output_token_account.to_account_info(),
        ctx.accounts.output_token_mint.to_account_info(),
        ctx.accounts.output_token_program.to_account_info(),
        output_transfer_amount,
        ctx.accounts.output_token_mint.decimals,
        &[&[crate::AUTH_SEED.as_bytes(), &[pool_state.auth_bump]]],
    )?;
```
