### Title
Flash-loan JIT liquidity attack allows sniping/stealing LP trading-fee yield via atomic deposit→swap→withdraw - (File: `programs/cp-swap/src/instructions/deposit.rs`, `programs/cp-swap/src/instructions/withdraw.rs`, `programs/cp-swap/src/instructions/swap_base_input.rs`)

### Summary
`deposit` and `withdraw` compute LP share amounts purely from the current vault balances (`vault_amount_without_fee`) with no minimum holding period, no per-slot/per-tx lock, and no check that the depositor has held shares for any length of time. Meanwhile, the LP-side portion of every swap's trade fee is added straight into the pool's vault balance (increasing `vault_amount_without_fee`) and is immediately reflected in the LP share price. Because there is no restriction preventing deposit and withdraw from occurring in the same transaction, an attacker can flash-loan tokens, deposit to acquire a large fraction of outstanding LP shares, trigger (or piggy-back on) a fee-generating swap, and withdraw immediately, capturing a disproportionate share of the LP fee that should have accrued to long-term liquidity providers — with zero holding-period risk.

### Finding Description
`deposit()` computes the caller's proportional entitlement using `pool_state.vault_amount_without_fee(...)` and `CurveCalculator::lp_tokens_to_trading_tokens`, and mints/burns LP supply immediately with no lock: [1](#0-0) 

`withdraw()` mirrors this with no delay or eligibility check tied to how long the caller has held LP tokens: [2](#0-1) 

`vault_amount_without_fee` only excludes the `protocol_fees`, `fund_fees`, and `creator_fees` ledgers from the LP share calculation — the LP-side portion of the trade fee is *not* excluded, meaning it is fully counted as part of the pool value backing outstanding LP shares: [3](#0-2) 

In `swap_base_input`, `input_amount_less_fees` (which becomes part of `new_input_vault_amount`) is `input_amount` minus only the protocol/fund/creator-tracked cut; the LP-fee remainder is transferred in full into the vault via `transfer_from_user_to_pool_vault(... input_transfer_amount ...)`, immediately raising `vault_amount_without_fee` and thus the LP share price for whoever holds shares at that instant: [4](#0-3) [5](#0-4) 

Because Solana transactions execute all contained instructions atomically and Anchor programs can be invoked multiple times per transaction, a single attacker-submitted transaction can sequence `deposit` → (a large `swap_base_input`/`swap_base_output`, either self-initiated or piggy-backed via priority ordering on a victim's swap) → `withdraw`, all against attacker-chosen token accounts, funded via a flash loan that is fully repayable within the same transaction. This is the exact "flash-loan stake" pattern from the reference report: acquire a large temporary share of the pool, let a fee event inflate the share price, then exit — capturing yield that should accrue only to liquidity providers who bear the pool's price/inventory risk over time.

### Impact Explanation
This allows theft of trading-fee yield from genuine liquidity providers: any LP fee generated while the flash depositor holds an inflated share of the pool is partially diverted to the attacker instead of remaining for long-term LPs, with the attacker bearing no market exposure (deposit and withdraw occur atomically at the same underlying price). This directly reduces returns for real LPs and, at scale/repetition, undermines the incentive to provide liquidity — matching the "theft of potential yield ... negative impact on protocol health" impact described in the reference report.

### Likelihood Explanation
No privileged role is required — `deposit`, `swap_base_input`/`swap_base_output`, and `withdraw` are all permissionless instructions reachable by any signer with attacker-chosen token accounts, and flash-loan capital is a standard, widely available primitive. The only requirements are enough capital (via flash loan) to dominate the pool's LP share temporarily and a fee-generating swap occurring within the same atomic bundle. No code path currently prevents deposit and withdraw from being combined in the same transaction/slot.

### Recommendation
Introduce a minimum holding period or same-block/same-transaction restriction between `deposit` and `withdraw` for a given depositor (e.g., disallow withdrawing LP shares minted in the same slot/transaction, or apply a time-weighted vesting on newly minted shares before they can capture accrued fee yield), consistent with the remediation suggested in the reference report ("do not allow users to deposit and withdraw in the same block").

### Proof of Concept
1. Attacker obtains a flash loan of token_0/token_1 sufficient to dominate the target pool's `lp_supply`.
2. In one transaction: call `deposit` with the borrowed tokens to mint a large fraction of LP shares (per `deposit.rs` logic, using current `vault_amount_without_fee`).
3. Still within the same transaction, execute (or be positioned around) a large `swap_base_input`/`swap_base_output`; the LP-fee portion of the trade is added to the vault balance per `swap_base_input.rs` L104-141/182-190, instantly raising the value backing all outstanding LP shares, including the attacker's freshly minted ones.
4. Call `withdraw` in the same transaction to redeem the inflated share value back to underlying tokens (per `withdraw.rs` logic).
5. Repay the flash loan; the attacker nets a share of the LP fee proportional to their temporary stake, diluting the yield of real, time-holding liquidity providers, with no price or duration risk taken.

### Citations

**File:** programs/cp-swap/src/instructions/deposit.rs (L99-114)
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
```

**File:** programs/cp-swap/src/instructions/withdraw.rs (L105-126)
```rust
    require_gt!(lp_token_amount, 0);
    require_gte!(ctx.accounts.owner_lp_token.amount, lp_token_amount);
    let pool_id = ctx.accounts.pool_state.key();
    let pool_state = &mut ctx.accounts.pool_state.load_mut()?;
    if !pool_state.get_status_by_bit(PoolStatusBitIndex::Withdraw) {
        return err!(ErrorCode::NotApproved);
    }
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

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L104-141)
```rust
    let constant_before = u128::from(total_input_token_amount)
        .checked_mul(u128::from(total_output_token_amount))
        .unwrap();

    let creator_fee_rate =
        pool_state.adjust_creator_fee_rate(ctx.accounts.amm_config.creator_fee_rate);
    let result = CurveCalculator::swap_base_input(
        u128::from(actual_amount_in),
        u128::from(total_input_token_amount),
        u128::from(total_output_token_amount),
        ctx.accounts.amm_config.trade_fee_rate,
        creator_fee_rate,
        ctx.accounts.amm_config.protocol_fee_rate,
        ctx.accounts.amm_config.fund_fee_rate,
        is_creator_fee_on_input,
    )
    .ok_or(ErrorCode::ZeroTradingTokens)?;

    let constant_after = u128::from(result.new_input_vault_amount)
        .checked_mul(u128::from(result.new_output_vault_amount))
        .unwrap();
    #[cfg(feature = "enable-log")]
    msg!(
        "input_amount:{}, output_amount:{}, trade_fee:{}, input_transfer_fee:{}, constant_before:{},constant_after:{}, is_creator_fee_on_input:{}, creator_fee:{}",
        result.input_amount,
        result.output_amount,
        result.trade_fee,
        transfer_fee,
        constant_before,
        constant_after,
        is_creator_fee_on_input,
        result.creator_fee,
    );
    require_eq!(
        u64::try_from(result.input_amount).unwrap(),
        actual_amount_in
    );
    let (input_transfer_amount, input_transfer_fee) = (amount_in, transfer_fee);
```

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L182-190)
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
```
