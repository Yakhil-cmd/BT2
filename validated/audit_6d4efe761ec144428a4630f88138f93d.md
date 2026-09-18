### Title
Withdrawal can burn a user's LP tokens while transferring zero underlying tokens back when paired with a Token-2022 transfer-fee mint - ([File: programs/cp-swap/src/instructions/withdraw.rs])

### Summary
`withdraw` computes the LP-token-to-underlying-token conversion, checks that the pre-fee `results.token_0_amount`/`results.token_1_amount` are non-zero, but never checks that the post-transfer-fee amount actually delivered to the user (`receive_token_0_amount` / `receive_token_1_amount`) is non-zero before burning the caller's LP tokens and issuing the transfer. `swap_base_input` explicitly guards against this exact scenario with `require_gt!(amount_received, 0)` after subtracting the transfer fee, but the analogous guard is missing in `withdraw`.

### Finding Description
In `withdraw`, the LP-to-token conversion result is checked only against zero pre-fee: [1](#0-0) 

The pre-fee amount is then reduced by the Token-2022 transfer fee to get the actual amount the user will receive: [2](#0-1) 

There is no `require_gt!(receive_token_0_amount, 0)` / `require_gt!(receive_token_1_amount, 0)` check here. The only downstream check is against the caller-supplied slippage minimums: [3](#0-2) 

If the caller passes `minimum_token_0_amount = 0` (or `minimum_token_1_amount = 0`), that check passes even when `receive_token_0_amount` (or `receive_token_1_amount`) is `0`. Execution then proceeds to burn the full `lp_token_amount` from the user and reduce `pool_state.lp_supply`: [4](#0-3) 

before calling `transfer_from_pool_vault_to_user`, which for `amount == 0` simply returns `Ok(())` without transferring anything: [5](#0-4) 

This is directly analogous to the referenced report: absence of a "you must receive a non-zero/minimum amount" check lets a user unknowingly lose funds — here, the withdrawing LP burns real LP tokens (a real economic claim on the pool) and receives nothing back for one or both sides of the pair. The condition is reachable whenever the output mint is a Token-2022 mint with a `TransferFeeConfig` extension whose fee (potentially `MAX_FEE_BASIS_POINTS`, i.e. up to 100%, or simply large relative to a small `token_0_amount`/`token_1_amount`) consumes the entire withdrawal amount for that side: [6](#0-5) 

Notably, `deposit` (the counterpart instruction) does have an equivalent zero-amount guard on `results.token_0_amount`/`results.token_1_amount` before fee adjustment, and `swap_base_input` explicitly enforces `require_gt!(amount_received, 0)` post-transfer-fee: [7](#0-6) [8](#0-7) 

`withdraw` is the one path in this instruction family missing the equivalent "must actually receive something" guard against transfer-fee erosion.

### Impact Explanation
A liquidity provider withdrawing from a pool whose one leg is a fee-on-transfer Token-2022 mint can have their LP tokens irrevocably burned and `pool_state.lp_supply` reduced while receiving zero tokens back for that leg, if they (knowingly or not, e.g. via a naive/default client that passes `0` for `minimum_token_X_amount`) don't specify a strictly positive minimum. This is a direct loss of the LP's economic claim on pool funds with no compensating transfer — a concrete loss-of-funds condition, matching the severity class of the referenced report (Medium).

### Likelihood Explanation
Requires a pool where one of the vault mints is Token-2022 with an actively configured transfer fee (already a first-class, supported feature per `get_transfer_fee`/`get_transfer_inverse_fee` and `is_supported_mint`), and either a small `lp_token_amount` relative to pool reserves or a high fee-basis-points/absolute-fee configuration that fully consumes the entitled `token_0_amount`/`token_1_amount`, combined with the caller supplying `minimum_token_0_amount`/`minimum_token_1_amount` of `0`. This is plausible for integrators/clients that don't compute a tight non-zero minimum, or for automated/small withdrawals.

### Recommendation
Add an explicit check after computing `receive_token_0_amount`/`receive_token_1_amount` (post transfer-fee) that both are non-zero (or require at least one side non-zero, depending on desired semantics), mirroring the `require_gt!(amount_received, 0)` guard already used in `swap_base_input`, so that a withdrawal cannot burn a user's LP tokens while delivering zero underlying tokens on either side.

### Proof of Concept
1. Create a pool where `token_0` (or `token_1`) is a Token-2022 mint with a `TransferFeeConfig` extension set to a high fee (e.g. `transfer_fee_basis_points = MAX_FEE_BASIS_POINTS` with a `maximum_fee` at least equal to the amount that will be withdrawn), per `get_transfer_fee`: [9](#0-8) 
2. LP deposits and receives LP tokens.
3. LP calls `withdraw` with a `lp_token_amount` small enough that `results.token_0_amount` (pre-fee entitlement) is non-zero but fully consumed by the mint's transfer fee, and passes `minimum_token_0_amount = 0`.
4. The `results.token_0_amount == 0` check at [10](#0-9)  passes (non-zero), but after fee subtraction `receive_token_0_amount == 0`.
5. The slippage check at [3](#0-2)  passes since `0 >= minimum_token_0_amount (0)`.
6. `pool_state.lp_supply` is decremented and the LP's tokens are burned at [4](#0-3) , while `transfer_from_pool_vault_to_user` transfers `0` (no-op) for that leg, leaving the LP with burned LP tokens and no corresponding token_0 received.

### Citations

**File:** programs/cp-swap/src/instructions/withdraw.rs (L116-126)
```rust
    let results = CurveCalculator::lp_tokens_to_trading_tokens(
        u128::from(lp_token_amount),
        u128::from(pool_state.lp_supply),
        u128::from(total_token_0_amount),
        u128::from(total_token_1_amount),
        RoundDirection::Floor,
    )
    .ok_or(ErrorCode::ZeroTradingTokens)?;
    if results.token_0_amount == 0 || results.token_1_amount == 0 {
        return err!(ErrorCode::ZeroTradingTokens);
    }
```

**File:** programs/cp-swap/src/instructions/withdraw.rs (L127-147)
```rust
    let token_0_amount = u64::try_from(results.token_0_amount).unwrap();
    let token_0_amount = std::cmp::min(total_token_0_amount, token_0_amount);
    let (receive_token_0_amount, token_0_transfer_fee) = {
        let transfer_fee =
            get_transfer_fee(&ctx.accounts.vault_0_mint.to_account_info(), token_0_amount)?;
        (
            token_0_amount.checked_sub(transfer_fee).unwrap(),
            transfer_fee,
        )
    };

    let token_1_amount = u64::try_from(results.token_1_amount).unwrap();
    let token_1_amount = std::cmp::min(total_token_1_amount, token_1_amount);
    let (receive_token_1_amount, token_1_transfer_fee) = {
        let transfer_fee =
            get_transfer_fee(&ctx.accounts.vault_1_mint.to_account_info(), token_1_amount)?;
        (
            token_1_amount.checked_sub(transfer_fee).unwrap(),
            transfer_fee,
        )
    };
```

**File:** programs/cp-swap/src/instructions/withdraw.rs (L172-176)
```rust
    if receive_token_0_amount < minimum_token_0_amount
        || receive_token_1_amount < minimum_token_1_amount
    {
        return Err(ErrorCode::ExceededSlippage.into());
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

**File:** programs/cp-swap/src/utils/token.rs (L44-56)
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
```

**File:** programs/cp-swap/src/utils/token.rs (L253-286)
```rust
/// Calculate the fee for output amount
pub fn get_transfer_inverse_fee(mint_info: &AccountInfo, post_fee_amount: u64) -> Result<u64> {
    if *mint_info.owner == Token::id() {
        return Ok(0);
    }
    if post_fee_amount == 0 {
        return err!(ErrorCode::InvalidInput);
    }
    let mint_data = mint_info.try_borrow_data()?;
    let mint = StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&mint_data)?;

    let fee = if let Ok(transfer_fee_config) = mint.get_extension::<TransferFeeConfig>() {
        let epoch = Clock::get()?.epoch;

        let transfer_fee = transfer_fee_config.get_epoch_fee(epoch);
        if u16::from(transfer_fee.transfer_fee_basis_points) == MAX_FEE_BASIS_POINTS {
            u64::from(transfer_fee.maximum_fee)
        } else {
            let transfer_fee = transfer_fee_config
                .calculate_inverse_epoch_fee(epoch, post_fee_amount)
                .unwrap();
            let transfer_fee_for_check = transfer_fee_config
                .calculate_epoch_fee(epoch, post_fee_amount.checked_add(transfer_fee).unwrap())
                .unwrap();
            if transfer_fee != transfer_fee_for_check {
                return err!(ErrorCode::TransferFeeCalculateNotMatch);
            }
            transfer_fee
        }
    } else {
        0
    };
    Ok(fee)
}
```

**File:** programs/cp-swap/src/utils/token.rs (L288-304)
```rust
/// Calculate the fee for input amount
pub fn get_transfer_fee(mint_info: &AccountInfo, pre_fee_amount: u64) -> Result<u64> {
    if *mint_info.owner == Token::id() {
        return Ok(0);
    }
    let mint_data = mint_info.try_borrow_data()?;
    let mint = StateWithExtensions::<spl_token_2022::state::Mint>::unpack(&mint_data)?;

    let fee = if let Ok(transfer_fee_config) = mint.get_extension::<TransferFeeConfig>() {
        transfer_fee_config
            .calculate_epoch_fee(Clock::get()?.epoch, pre_fee_amount)
            .unwrap()
    } else {
        0
    };
    Ok(fee)
}
```

**File:** programs/cp-swap/src/instructions/deposit.rs (L103-113)
```rust
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
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L142-156)
```rust
    let (output_transfer_amount, output_transfer_fee) = {
        let amount_out = u64::try_from(result.output_amount).unwrap();
        let transfer_fee = get_transfer_fee(
            &ctx.accounts.output_token_mint.to_account_info(),
            amount_out,
        )?;
        let amount_received = amount_out.checked_sub(transfer_fee).unwrap();
        require_gt!(amount_received, 0);
        require_gte!(
            amount_received,
            minimum_amount_out,
            ErrorCode::ExceededSlippage
        );
        (amount_out, transfer_fee)
    };
```
