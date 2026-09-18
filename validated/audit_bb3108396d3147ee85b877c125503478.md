Based on my analysis, I've confirmed the analog exists in this codebase.

### Title
LP trading fees are credited instantly and without lock, enabling JIT/sandwich extraction of LP fee yield - (File: `programs/cp-swap/src/instructions/swap_base_input.rs`, `programs/cp-swap/src/instructions/deposit.rs`, `programs/cp-swap/src/instructions/withdraw.rs`)

### Summary
In `swap_base_input`/`swap_base_output`, the LP-retained portion of the trade fee (`trade_fee` minus `protocol_fee`/`fund_fee`/`creator_fee`) is added directly to the input vault balance and immediately backs outstanding LP tokens, exactly like the Yieldy `LiquidityReserve` yield reported in the external report. Because `deposit` and `withdraw` have no lock-up, cool-down, or exit fee, an attacker can deposit large liquidity immediately before a big swap and withdraw immediately after, capturing a disproportionate share of that swap's fee at the expense of passive LPs.

### Finding Description
`CurveCalculator::swap_base_input` computes `trade_fee = Fees::trading_fee(input_amount, trade_fee_rate)`, then splits out `protocol_fee` and `fund_fee` as portions of `trade_fee`, but only subtracts the *full* `trade_fee` from `input_amount` before running the constant-product math (`input_amount_less_fees = input_amount - trade_fee`), see [1](#0-0) . The actual token transfer into the vault carries the *full* `amount_in` (including the entire trade fee), as seen in `swap_base_input.rs` where `input_transfer_amount = amount_in` [2](#0-1) . Only `protocol_fee` and `fund_fee` (and `creator_fee`) are earmarked in `pool_state.update_fees` and later excluded from LP-share calculations via `vault_amount_without_fee`, which subtracts `protocol_fees_token_x + fund_fees_token_x + creator_fees_token_x` from the raw vault balance [3](#0-2) . The remainder of the trade fee (LP fee minus protocol/fund/creator cut) therefore sits in the vault as unearmarked balance and instantly increases the value backing all outstanding LP tokens the moment the swap lands.

`deposit` and `withdraw` compute the caller's share of the pool using this same instantaneously-updated vault balance via `vault_amount_without_fee` and `CurveCalculator::lp_tokens_to_trading_tokens` [4](#0-3) [5](#0-4) . Neither instruction imposes a minimum holding period, exit fee, or delayed settlement — `withdraw` burns LP tokens and pays out the current pro-rata share immediately [6](#0-5) , and `deposit` mints LP tokens for the current pro-rata price immediately [7](#0-6) . This mirrors the exact root cause in the Yieldy report: fees are distributed to whoever holds LP shares at settlement time, with no vesting or lock, so instantaneous add/remove liquidity captures a pro-rata slice of any single large fee event.

### Impact Explanation
An attacker who anticipates (or bundles, e.g., via Jito) a large `swap_base_input`/`swap_base_output` call can: (1) `deposit` a large amount of liquidity immediately before the swap, (2) let the swap execute and inflate the vault balance backing LP shares by the LP's portion of the trade fee, (3) `withdraw` immediately after, extracting a large fraction of that fee that would otherwise have accrued to genuine, passive LPs. This is a real transfer of value (theft of LP yield) from passive liquidity providers to the JIT attacker, reducing the incentive to provide durable liquidity and degrading LP returns, consistent with the accepted High-severity Yieldy finding.

### Likelihood Explanation
This requires the attacker to control transaction ordering around a large, known swap — achievable today on Solana via priority fees or MEV bundle services (e.g., Jito) without any validator collusion or leaked keys, using only the public `deposit`/`swap_base_input`/`withdraw` instructions with attacker-chosen accounts. It is more attractive for larger swaps/pools with low fee-tier competition, and is a well-known, broadly-applicable AMM design pattern (as also acknowledged by the original Yieldy maintainers) rather than a one-off implementation bug, making it moderately likely to be exploited against high-volume pools.

### Recommendation
- Introduce a short minimum liquidity lock-up (e.g., a required number of slots) after `deposit` before a corresponding `withdraw` from the same authority can be processed for that position.
- Alternatively, accrue and vest the LP-retained fee portion over multiple slots/epochs rather than crediting it to the instantaneous vault balance used for LP share pricing.
- Consider a small withdrawal fee that is redistributed to remaining LPs, making JIT round-trips unprofitable.

### Proof of Concept
1. Attacker observes (or bundles atomically alongside) a pending large `swap_base_input` transaction against pool `P`.
2. Attacker calls `deposit` with a large `lp_token_amount`, minting LP tokens at the pre-swap price [7](#0-6) .
3. The victim's `swap_base_input` executes, adding the full `trade_fee` (minus protocol/fund/creator cut) to the input vault, instantly increasing the value per LP token via `update_fees`/`vault_amount_without_fee` [8](#0-7) .
4. Attacker immediately calls `withdraw` for the same `lp_token_amount`, redeeming at the post-swap, fee-inflated price and capturing a pro-rata share of the trade fee with negligible market exposure [6](#0-5) .

### Citations

**File:** programs/cp-swap/src/curve/calculator.rs (L108-118)
```rust
        let input_amount_less_fees = if is_creator_fee_on_input {
            let total_fee = Fees::trading_fee(input_amount, trade_fee_rate + creator_fee_rate)?;
            creator_fee = Fees::split_creator_fee(total_fee, trade_fee_rate, creator_fee_rate)?;
            trade_fee = total_fee - creator_fee;
            input_amount.checked_sub(total_fee)?
        } else {
            trade_fee = Fees::trading_fee(input_amount, trade_fee_rate)?;
            input_amount.checked_sub(trade_fee)?
        };
        let protocol_fee = Fees::protocol_fee(trade_fee, protocol_fee_rate)?;
        let fund_fee = Fees::fund_fee(trade_fee, fund_fee_rate)?;
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L141-141)
```rust
    let (input_transfer_amount, input_transfer_fee) = (amount_in, transfer_fee);
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

**File:** programs/cp-swap/src/states/pool.rs (L200-220)
```rust
    pub fn vault_amount_without_fee(&self, vault_0: u64, vault_1: u64) -> Result<(u64, u64)> {
        let fees_token_0 = self
            .protocol_fees_token_0
            .checked_add(self.fund_fees_token_0)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_add(self.creator_fees_token_0)
            .ok_or(ErrorCode::MathOverflow)?;
        let fees_token_1 = self
            .protocol_fees_token_1
            .checked_add(self.fund_fees_token_1)
            .ok_or(ErrorCode::MathOverflow)?
            .checked_add(self.creator_fees_token_1)
            .ok_or(ErrorCode::MathOverflow)?;
        Ok((
            vault_0
                .checked_sub(fees_token_0)
                .ok_or(ErrorCode::InsufficientVault)?,
            vault_1
                .checked_sub(fees_token_1)
                .ok_or(ErrorCode::InsufficientVault)?,
        ))
```

**File:** programs/cp-swap/src/instructions/deposit.rs (L99-110)
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
```

**File:** programs/cp-swap/src/instructions/deposit.rs (L192-201)
```rust
    pool_state.lp_supply = pool_state.lp_supply.checked_add(lp_token_amount).unwrap();

    token_mint_to(
        ctx.accounts.authority.to_account_info(),
        ctx.accounts.token_program.to_account_info(),
        ctx.accounts.lp_mint.to_account_info(),
        ctx.accounts.owner_lp_token.to_account_info(),
        lp_token_amount,
        &[&[crate::AUTH_SEED.as_bytes(), &[pool_state.auth_bump]]],
    )?;
```

**File:** programs/cp-swap/src/instructions/withdraw.rs (L112-126)
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
        RoundDirection::Floor,
    )
    .ok_or(ErrorCode::ZeroTradingTokens)?;
    if results.token_0_amount == 0 || results.token_1_amount == 0 {
        return err!(ErrorCode::ZeroTradingTokens);
    }
```

**File:** programs/cp-swap/src/instructions/withdraw.rs (L178-202)
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

```
