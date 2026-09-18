### Title
Withdraw reverts and permanently blocks LP redemption when either computed trading-token amount rounds down to zero - (File: programs/cp-swap/src/instructions/withdraw.rs)

### Summary
The `withdraw` instruction requires that **both** `token_0_amount` and `token_1_amount` computed from a user's LP share be non-zero, or the entire transaction reverts. In a pool that becomes reserve-imbalanced (e.g. after heavy one-sided swapping or due to disparate token decimals), a small LP holder's proportional share of one vault can floor-round to zero while their share of the other vault is still meaningfully positive. Because the check is an OR-condition that aborts the whole withdrawal rather than allowing the non-zero side to be redeemed, such holders can become unable to redeem *any* of their entitled tokens even though the pool still holds value on their behalf — directly analogous to the Dopex `PerpetualAtlanticVaultLP.redeem()` bug where `require(assets != 0)` blocked redemption entirely whenever one asset's computed value was zero, ignoring value the user was owed in the other asset.

### Finding Description
`withdraw()` computes both trading-token amounts via `CurveCalculator::lp_tokens_to_trading_tokens` with `RoundDirection::Floor`, then enforces: [1](#0-0) 

```rust
let results = CurveCalculator::lp_tokens_to_trading_tokens(...RoundDirection::Floor)
    .ok_or(ErrorCode::ZeroTradingTokens)?;
if results.token_0_amount == 0 || results.token_1_amount == 0 {
    return err!(ErrorCode::ZeroTradingTokens);
}
```

The underlying math is a simple floor division of the user's proportional share: [2](#0-1) 

If `token_1_vault_amount` is small relative to `lp_token_supply` (which happens naturally when the pool becomes skewed toward token_0, or when token_1 has fewer decimals / lower unit value than token_0), then `lp_token_amount * token_1_vault_amount / lp_token_supply` rounds to `0` for holders whose LP balance is a small fraction of supply — even though `token_0_amount` for the same withdrawal is non-zero and meaningful. The `||` check reverts the whole call in this case, denying the user access to the token_0 amount they are legitimately owed. Since `lp_token_amount` passed to `withdraw` is bounded above by the caller's own `owner_lp_token.amount` (`require_gte!(ctx.accounts.owner_lp_token.amount, lp_token_amount)`), a holder with a small enough balance cannot escape the zero-rounding by choosing a larger amount — even withdrawing their *entire* balance in one call still computes zero for the illiquid side, so the withdrawal path is unconditionally blocked for that user until the vault ratio changes favorably (which, for a small holder, generally only gets worse as `lp_supply` grows with further deposits).

This is the direct structural analog of the referenced Dopex finding: a `require`/`if` check tests a computed "assets" value that is derived from only one side of a two-asset position and reverts on zero, discarding the fact that the other side still holds redeemable value for the user.

### Impact Explanation
Small LP holders in an imbalanced pool (imbalance driven by ordinary swap activity that is fully reachable by any unprivileged trader via `swap_base_input`/`swap_base_output`, or inherent from differing token decimals) can find their LP position effectively frozen: `withdraw` reverts for any `lp_token_amount` they can supply, so they cannot recover the non-zero-side tokens they are owed. This is a freezing-of-funds condition for affected LPs, reachable purely through normal permissionless pool usage (swaps that shift reserve ratios) without any privileged action.

### Likelihood Explanation
Likelihood is data/state dependent (Medium): it requires a sufficiently skewed vault ratio combined with a small LP balance relative to `lp_supply`. This condition arises naturally as a side effect of normal trading pushing the constant-product curve to one side, or from pools pairing tokens with very different decimal counts/values, and does not require any privileged signer or malicious validator — any user's ordinary swaps can push the ratio into this regime, at which point pre-existing small LP holders are impacted. This mirrors the judge's own assessment of the original report ("extreme … due to reliance on external condition" → Medium).

### Recommendation
Do not abort the entire withdrawal when only one side rounds to zero. Instead, allow redemption of whichever side(s) computed a non-zero amount (analogous to the report's suggested `require((assets + rdpxAmount) != 0)` fix), or change the check to `results.token_0_amount == 0 && results.token_1_amount == 0` so the call only reverts when the withdrawer would receive absolutely nothing, rather than when either individual side is dust.

### Proof of Concept
1. Pool is created and several users deposit, with one user (`Alice`) minting a very small proportion of `lp_supply` relative to total token_1 reserves (e.g., due to token_1 having far fewer decimals, or joining when the pool is already large).
2. Other unprivileged traders repeatedly call `swap_base_input`/`swap_base_output` (fully permissionless, single-transaction, attacker- or market-driven), pushing the constant-product reserves so that `token_1_vault_amount` becomes very small relative to `lp_supply` while `token_0_vault_amount` remains large.
3. Alice calls `withdraw` with `lp_token_amount` equal to her full LP balance (the maximum allowed by `require_gte!(owner_lp_token.amount, lp_token_amount)`).
4. `CurveCalculator::lp_tokens_to_trading_tokens` computes `results.token_1_amount == 0` (floor division rounds to zero) while `results.token_0_amount > 0`.
5. The check at [3](#0-2)  triggers `ErrorCode::ZeroTradingTokens`, reverting the transaction — Alice cannot withdraw the `token_0_amount` she is entitled to, and has no way to change the outcome since she cannot supply a larger `lp_token_amount` than her own balance.

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

**File:** programs/cp-swap/src/curve/constant_product.rs (L57-64)
```rust
        let mut token_0_amount = lp_token_amount
            .checked_mul(token_0_vault_amount)?
            .checked_div(lp_token_supply)?;
        let mut token_1_amount = lp_token_amount
            .checked_mul(token_1_vault_amount)?
            .checked_div(lp_token_supply)?;
        let (token_0_amount, token_1_amount) = match round_direction {
            RoundDirection::Floor => (token_0_amount, token_1_amount),
```
