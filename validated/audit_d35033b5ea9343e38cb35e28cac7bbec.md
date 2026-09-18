### Title
Deposit executes token transfers before crediting LP-share state, violating checks-effects-interactions — (File: `programs/cp-swap/src/instructions/deposit.rs`)

### Summary
The external report's bug class is "external call performed before state update, enabling reentrancy." In `raydium-cp-swap--004`, `swap_base_input`/`swap_base_output`/`withdraw` all update `pool_state` (fees, `lp_supply`, burn) **before** invoking the token-transfer CPIs, which is the safe ordering. `deposit`, however, does the opposite: it performs both `transfer_from_user_to_pool_vault` CPIs first, and only afterwards increments `pool_state.lp_supply` and mints LP tokens via `token_mint_to`. [1](#0-0) 

### Finding Description
`deposit()` computes `results` (token_0/token_1 amounts owed) from the currently-loaded `pool_state.lp_supply` and vault balances, then calls `transfer_from_user_to_pool_vault` for token_0 and token_1 (external CPIs into the token program), and only after both transfers complete does it update `pool_state.lp_supply` and call `token_mint_to` to mint LP tokens to the depositor. [2](#0-1) [3](#0-2) 

This is structurally the same anti-pattern flagged in the report: the state that determines share pricing (`lp_supply`) is not updated until after an external call that can transfer control away from the program. The token transfer helper unconditionally issues `token_2022::transfer_checked`, which for Token-2022 mints can invoke arbitrary extension logic (e.g., a transfer-hook program) before returning control to `cp-swap`. [4](#0-3) 

By contrast, `withdraw()` and both swap instructions perform the state mutation (`lp_supply` decrement/burn, or `update_fees`) *before* the outbound transfer CPIs, correctly following checks-effects-interactions. [5](#0-4) [6](#0-5) 

### Impact Explanation
I was **not able to confirm this is actually exploitable** in this codebase, for two important reasons I could not fully resolve given available tooling:
1. Solana CPI reentrancy is fundamentally different from EVM: the token program (`token_2022::transfer_checked`) does not call back into the invoking program unless a Token-2022 mint extension (transfer hook) is configured to CPI to a third-party program, and that hook program would need to be able to re-invoke `cp-swap`'s own instructions with the required signer/PDA accounts to cause any damage.
2. The codebase has a mint-extension allow-list mechanism (`is_supported_mint`, `SupportMintAssociated`) referenced in `programs/cp-swap/src/utils/token.rs` and `programs/cp-swap/src/instructions/admin/*_support_mint_associated.rs`, and I could not confirm from the index whether `TransferHook`-extension mints are rejected at `initialize`/`initialize_with_permission` time (my search for `is_supported_mint` usage inside `initialize.rs` returned no matches, but this may be a limitation of the search rather than proof it's absent).

Because I could not verify (a) whether Token-2022 mints with the `TransferHook` extension are actually permitted into a pool's `token_0_vault`/`token_1_vault`, and (b) whether such a hook could practically re-enter `deposit`/`withdraw`/`swap` with the necessary signer context to manipulate `lp_supply` accounting, I cannot confirm concrete theft or unbacked LP minting is reachable via a single attacker-controlled transaction. This is a legitimate code-ordering weakness worth hardening, but it does not meet the bar of "proven" exploitability required by the validation rules without further investigation (ideally requiring full source access to `initialize.rs`/`is_supported_mint` enforcement, which the current index does not fully expose).

### Likelihood Explanation
Low-to-uncertain: exploitation would require a pool to hold a Token-2022 mint with a transfer-hook extension whose hook program is malicious/attacker-controlled, and for that mint to pass whatever extension whitelist exists at pool-initialization. I could not confirm this whitelist behavior with certainty from the available code.

### Recommendation
Regardless of exploitability confirmation, reorder `deposit()` so that `pool_state.lp_supply` is incremented and LP tokens minted before the outbound token transfers are executed — mirroring the (correct) ordering already used in `withdraw()` and the swap instructions — to eliminate any external-call-before-state-update window.

### Proof of Concept
Not constructible with confidence from the available index: a full PoC would require confirming (1) that Token-2022 `TransferHook`-extension mints are accepted by `initialize`/`initialize_with_permission`, and (2) that a hook program invoked during `transfer_from_user_to_pool_vault` can re-enter `deposit` (or another state-mutating instruction) using the still-valid transaction-wide signer flag of the `owner` account. I recommend a Devin/engineer session with full repo access to inspect `programs/cp-swap/src/instructions/initialize.rs`, `initialize_with_permission.rs`, and `states/support_mint_associated.rs` in full to settle this before treating the finding as confirmed-exploitable.

### Citations

**File:** programs/cp-swap/src/instructions/deposit.rs (L99-132)
```rust
    let (total_token_0_amount, total_token_1_amount) = pool_state.vault_amount_without_fee(
        ctx.accounts.token_0_vault.amount,
        ctx.accounts.token_1_vault.amount,
    )?;
    let results = CurveCalculator::lp_tokens_to_trading_tokens(
        u128::from(lp_token_amount),
        u128::from(pool_state.lp_supply),
        u128::from(total_token_0_amount),
        u128::from(total_token_1_amount),
        RoundDirection::Ceiling,
    )
    .ok_or(ErrorCode::ZeroTradingTokens)?;
    if results.token_0_amount == 0 || results.token_1_amount == 0 {
        return err!(ErrorCode::ZeroTradingTokens);
    }
    let token_0_amount = u64::try_from(results.token_0_amount).unwrap();
    let (transfer_token_0_amount, transfer_token_0_fee) = {
        let transfer_fee =
            get_transfer_inverse_fee(&ctx.accounts.vault_0_mint.to_account_info(), token_0_amount)?;
        (
            token_0_amount.checked_add(transfer_fee).unwrap(),
            transfer_fee,
        )
    };

    let token_1_amount = u64::try_from(results.token_1_amount).unwrap();
    let (transfer_token_1_amount, transfer_token_1_fee) = {
        let transfer_fee =
            get_transfer_inverse_fee(&ctx.accounts.vault_1_mint.to_account_info(), token_1_amount)?;
        (
            token_1_amount.checked_add(transfer_fee).unwrap(),
            transfer_fee,
        )
    };
```

**File:** programs/cp-swap/src/instructions/deposit.rs (L164-202)
```rust
    transfer_from_user_to_pool_vault(
        ctx.accounts.owner.to_account_info(),
        ctx.accounts.token_0_account.to_account_info(),
        ctx.accounts.token_0_vault.to_account_info(),
        ctx.accounts.vault_0_mint.to_account_info(),
        if ctx.accounts.vault_0_mint.to_account_info().owner == ctx.accounts.token_program.key {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        },
        transfer_token_0_amount,
        ctx.accounts.vault_0_mint.decimals,
    )?;

    transfer_from_user_to_pool_vault(
        ctx.accounts.owner.to_account_info(),
        ctx.accounts.token_1_account.to_account_info(),
        ctx.accounts.token_1_vault.to_account_info(),
        ctx.accounts.vault_1_mint.to_account_info(),
        if ctx.accounts.vault_1_mint.to_account_info().owner == ctx.accounts.token_program.key {
            ctx.accounts.token_program.to_account_info()
        } else {
            ctx.accounts.token_program_2022.to_account_info()
        },
        transfer_token_1_amount,
        ctx.accounts.vault_1_mint.decimals,
    )?;

    pool_state.lp_supply = pool_state.lp_supply.checked_add(lp_token_amount).unwrap();

    token_mint_to(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_program.to_account_info(),
        ctx.accounts.lp_mint.to_account_info(),
        ctx.accounts.owner_lp_token.to_account_info(),
        lp_token_amount,
        &[&[crate::AUTH_SEED.as_bytes(), &[pool_state.auth_bump]]],
    )?;
    pool_state.recent_epoch = Clock::get()?.epoch;
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

**File:** programs/cp-swap/src/instructions/withdraw.rs (L178-186)
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
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L158-163)
```rust
    pool_state.update_fees(
        u64::try_from(result.protocol_fee).unwrap(),
        u64::try_from(result.fund_fee).unwrap(),
        u64::try_from(result.creator_fee).unwrap(),
        trade_direction,
    )?;
```
