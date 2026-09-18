### Title
`withdraw()` reverts entirely and permanently freezes LP tokens when the proportional redemption amount rounds down to zero - (File: `programs/cp-swap/src/instructions/withdraw.rs`)

### Summary
`withdraw()` computes each LP holder's proportional share of `token_0`/`token_1` via `CurveCalculator::lp_tokens_to_trading_tokens` and unconditionally reverts the entire instruction with `ErrorCode::ZeroTradingTokens` if either resulting amount is `0`. Since burning LP tokens is only possible through this same instruction, any LP position whose proportional redemption rounds down to zero for either token becomes permanently unredeemable, mirroring the referenced Votium finding where a hard, all-or-nothing threshold check collapsed the entire reinvestment flow instead of degrading gracefully.

### Finding Description
`withdraw` requires both computed trading-token amounts to be non-zero or the whole call reverts: [1](#0-0) 

The trading token amounts are a straightforward proportional floor-division: `lp_token_amount * vault_amount / lp_supply`, floored: [2](#0-1) 

Because vault balances (`token_0_vault.amount`, `token_1_vault.amount`) are read live from the token accounts and are not otherwise capped or normalized, any imbalance between the two sides of the pool (e.g. very different token decimals, or one side's reserve growing much larger relative to `lp_supply` than the other, including via direct external transfers into the vault) can push the proportional share of the *smaller*-relative-value token down to `0` for a given LP holder's balance, no matter what `lp_token_amount` they request (including withdrawing their entire balance at once). In that situation:
- `deposit()` has the identical zero-check and will simply refuse further deposits (no direct fund loss, just griefed availability): [3](#0-2) 
- `withdraw()` has the same zero-check, but unlike a failed deposit, a failed withdraw means the caller cannot redeem LP tokens they already hold and paid real capital for. There is no alternate unprivileged instruction to burn LP tokens or reclaim the underlying assets.

This is structurally the same bug class as the referenced Votium `applyRewards()` finding: a downstream operation enforces an implicit "minimum acceptable amount" (there, `SafEth.minAmount`; here, "amount must round to non-zero on both legs") and, instead of gracefully handling the sub-threshold case (partial success, fallback, or accepting a `0` transfer on one leg), the entire transaction — and with it the user's only path to their funds — reverts unconditionally.

### Impact Explanation
Any LP provider whose proportional share of one of the pool's two tokens is calculated as `0` (due to floor rounding against a skewed vault ratio) is permanently unable to call `withdraw()`, because every attempt — regardless of the `lp_token_amount` chosen — hits the same `require`/`err!(ErrorCode::ZeroTradingTokens)` check. Since minting/burning `lp_mint` outside of `deposit`/`withdraw` is not exposed to users, this constitutes a permanent freeze of that LP holder's deposited funds. This is a Medium-severity accounting/availability defect: it does not immediately let an attacker steal funds, but it can permanently lock legitimate LP funds in a pool with skewed reserves (e.g., extreme token decimal mismatches, or pools whose vault ratio has been pushed to an extreme via legitimate trading or direct vault donations).

### Likelihood Explanation
Likelihood is elevated for pools with large decimal disparities between `token_0` and `token_1` mints, or pools where trading/donations push the vault ratio to an extreme relative to `lp_supply`. Any unprivileged party can create such a pool via `initialize`/`initialize_with_permission`, and any unprivileged LP (including a victim depositor) can subsequently be pushed into this rounding trap purely through normal `swap_base_input`/`swap_base_output` activity that shifts vault balances, without any privileged action required.

### Recommendation
- Do not hard-revert the entire `withdraw()` call when one side rounds to zero; instead allow a `0` transfer on that leg (skip the CPI for the zero side) while still burning LP tokens and transferring the non-zero side, similar in spirit to allowing partial/degraded execution instead of an all-or-nothing failure.
- Alternatively, round `lp_tokens_to_trading_tokens` results up (e.g., ceiling) for the withdrawal path so a non-zero LP balance always yields a non-zero token amount on both sides, or track fractional/dust balances so users can eventually exit.
- At minimum, document/guard against extreme decimal or ratio skew at pool `initialize` time so this state is unreachable, matching the "long term: remove/relax the hard minimum" resolution applied in the referenced report.

### Proof of Concept
1. Create a pool via `initialize` with `token_0` having 0 decimals and `token_1` having 9 decimals (or otherwise ensure the vault ratio can grow highly skewed), and mint a modest initial LP supply.
2. Perform normal swaps (`swap_base_input`/`swap_base_output`) that drive the `token_0_vault` reserve to a very large multiple of `lp_supply` relative to a minority LP holder's share, or directly transfer extra `token_0` into the vault (vault balance is read live, not vault-tracked separately).
3. Have the minority LP holder call `withdraw()` with their full `lp_token_amount`. `CurveCalculator::lp_tokens_to_trading_tokens` (`programs/cp-swap/src/curve/calculator.rs:205-219`) floors their `token_1` (or `token_0`) share to `0`.
4. `withdraw()` hits `if results.token_0_amount == 0 || results.token_1_amount == 0 { return err!(ErrorCode::ZeroTradingTokens); }` (`programs/cp-swap/src/instructions/withdraw.rs:124-126`) and reverts unconditionally — for every possible `lp_token_amount` the holder could pass — permanently freezing their LP position.

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

**File:** programs/cp-swap/src/curve/calculator.rs (L203-219)
```rust
    /// Get the amount of trading tokens for the given amount of pool tokens,
    /// provided the total trading tokens and supply of pool tokens.
    pub fn lp_tokens_to_trading_tokens(
        lp_token_amount: u128,
        lp_token_supply: u128,
        token_0_vault_amount: u128,
        token_1_vault_amount: u128,
        round_direction: RoundDirection,
    ) -> Option<TradingTokenResult> {
        ConstantProductCurve::lp_tokens_to_trading_tokens(
            lp_token_amount,
            lp_token_supply,
            token_0_vault_amount,
            token_1_vault_amount,
            round_direction,
        )
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
