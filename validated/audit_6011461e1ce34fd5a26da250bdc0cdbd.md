### Title
Per-swap floor-division of `protocol_fee`/`fund_fee` lets an attacker split a swap into many small swaps to shift protocol/fund revenue to LPs - ([File: programs/cp-swap/src/curve/fees.rs])

### Summary
`Fees::protocol_fee` and `Fees::fund_fee` are computed independently on every single `swap_base_input`/`swap_base_output` call using floor division of the per-call `trade_fee`, with no accumulator across calls. Because `trade_fee` itself is rounded **up** (`ceil_div`) but the protocol's/fund's cut of that fee is rounded **down** (`floor_div`), a trader who splits one large swap into many tiny swaps can repeatedly cause `protocol_fee` and `fund_fee` to truncate to 0 while `trade_fee` still accrues (and stays in the pool, benefiting LPs). This reproduces the reported bug class ("fulfilling a small quantity portion" causes the fee split to lose precision every time it's recomputed) applied to raydium-cp-swap's swap fee split.

### Finding Description
`Fees::trading_fee` rounds the total trade fee **up**: [1](#0-0) [2](#0-1) 

but `Fees::protocol_fee` and `Fees::fund_fee` round the protocol's/fund's share of that fee **down** via `floor_div`: [3](#0-2) [4](#0-3) 

`CurveCalculator::swap_base_input` (and `swap_base_output`) recompute `trade_fee`, `protocol_fee`, and `fund_fee` fresh for every single swap call - there is no running/cumulative fee ledger that would let fractional remainders carry over between swaps: [5](#0-4) 

For a minimal input amount, `ceil_div` guarantees `trade_fee >= 1` as soon as `trade_fee_rate > 0`, but `floor_div(trade_fee, protocol_fee_rate, FEE_RATE_DENOMINATOR_VALUE)` truncates to `0` whenever `trade_fee * protocol_fee_rate < FEE_RATE_DENOMINATOR_VALUE` (1,000,000). With realistic config values (e.g. `protocol_fee_rate = 1000` i.e. 0.1%, as used in the repo's own test setup), this means the *entire* protocol/fund cut is silently dropped to 0 for any `trade_fee` below roughly 1,000 units, which is common for small swap amounts.

The per-swap result is passed straight into `pool_state.update_fees`, which permanently commits whatever `protocol_fee`/`fund_fee` was computed for that single call into the pool's fee ledger: [6](#0-5) [7](#0-6) 

Critically, `trade_fee` itself is *not* separately deducted from the vault beyond what is already folded into `input_amount_less_fees` - it stays in `new_input_vault_amount`/the pool reserves, i.e., it accrues to LPs via the constant-product invariant regardless of whether `protocol_fee`/`fund_fee` rounded to zero. So splitting a swap into many tiny swaps does not cost the attacker any extra fee overall (each tiny swap still pays `trade_fee>=1`), but it systematically starves `protocol_fees_token_x`/`fund_fees_token_x` (used later in `collect_protocol_fee`/`collect_fund_fee`) relative to what a single equivalent large swap would have generated, shifting that value to LPs instead.

### Impact Explanation
Any unprivileged trader can reachably reduce the protocol's and fund owner's fee income accrual on `swap_base_input`/`swap_base_output` simply by issuing many small-amount swaps instead of one large swap, with `protocol_fees_token_0/1` and `fund_fees_token_0/1` under-accruing versus the economically correct amount. This is a fee-ledger accounting discrepancy directly reachable from a single submitted swap transaction repeated with attacker-chosen small `amount_in`/`amount_out` values, matching the reported bug class of per-fill fee-rounding causing systemic protocol income loss.

### Likelihood Explanation
High for an attacker (or a natural pattern of many retail-sized swaps) willing to submit multiple transactions instead of one; each individual transaction is a normal, permitted `swap_base_input`/`swap_base_output` call with no special preconditions, and the effect compounds automatically because `protocol_fee`/`fund_fee` are recomputed and floored independently on every call.

### Recommendation
Track fractional/sub-unit remainders of `protocol_fee` and `fund_fee` across swaps (e.g., accumulate in higher precision or carry a remainder in `PoolState`) instead of independently flooring each call's tiny `trade_fee` share, or compute protocol/fund fee shares with rounding that biases toward the protocol (e.g., `ceil_div`) similar to how `trade_fee` itself is computed, bounded so the sum of fee components never exceeds `trade_fee`.

### Proof of Concept
1. Configure an `AmmConfig` with `trade_fee_rate = 2500` (0.25%) and `protocol_fee_rate = 1000` (0.1% of trade fee), as used in `tests/utils` fixtures.
2. Call `swap_base_input` once with `amount_in = X` such that `trade_fee = ceil_div(X, 2500, 1_000_000)` is, say, `500` (still `protocol_fee = floor_div(500, 1000, 1_000_000) = 0`).
3. Instead of one such swap, split `X` into `N` separate `swap_base_input` calls each with `amount_in = X/N`, chosen small enough that each call's `trade_fee` stays low; `protocol_fee`/`fund_fee` truncate to `0` on every call via [4](#0-3) , while `trade_fee` per call is still `>=1` and is folded into the vault (LPs), per [5](#0-4) .
4. After `N` swaps, `pool_state.protocol_fees_token_x`/`fund_fees_token_x` (per [7](#0-6) ) show `0` accrued protocol/fund fee, whereas a single equivalent large swap would have accrued a nonzero `protocol_fee`/`fund_fee`, demonstrating the income diversion from protocol/fund to LPs.

### Citations

**File:** programs/cp-swap/src/curve/fees.rs (L7-16)
```rust
fn ceil_div(token_amount: u128, fee_numerator: u128, fee_denominator: u128) -> Option<u128> {
    if fee_denominator == 0 {
        return None;
    }
    token_amount
        .checked_mul(u128::from(fee_numerator))?
        .checked_add(fee_denominator)?
        .checked_sub(1)?
        .checked_div(fee_denominator)
}
```

**File:** programs/cp-swap/src/curve/fees.rs (L18-26)
```rust
/// Helper function for calculating swap fee
pub fn floor_div(token_amount: u128, fee_numerator: u128, fee_denominator: u128) -> Option<u128> {
    if fee_denominator == 0 {
        return None;
    }
    token_amount
        .checked_mul(fee_numerator)?
        .checked_div(fee_denominator)
}
```

**File:** programs/cp-swap/src/curve/fees.rs (L30-36)
```rust
    pub fn trading_fee(amount: u128, trade_fee_rate: u64) -> Option<u128> {
        ceil_div(
            amount,
            u128::from(trade_fee_rate),
            u128::from(FEE_RATE_DENOMINATOR_VALUE),
        )
    }
```

**File:** programs/cp-swap/src/curve/fees.rs (L38-54)
```rust
    /// Calculate the owner protocol fee in trading tokens
    pub fn protocol_fee(amount: u128, protocol_fee_rate: u64) -> Option<u128> {
        floor_div(
            amount,
            u128::from(protocol_fee_rate),
            u128::from(FEE_RATE_DENOMINATOR_VALUE),
        )
    }

    /// Calculate the owner fund fee in trading tokens
    pub fn fund_fee(amount: u128, fund_fee_rate: u64) -> Option<u128> {
        floor_div(
            amount,
            u128::from(fund_fee_rate),
            u128::from(FEE_RATE_DENOMINATOR_VALUE),
        )
    }
```

**File:** programs/cp-swap/src/curve/calculator.rs (L104-118)
```rust
    ) -> Option<SwapResult> {
        let mut creator_fee = 0;
        let trade_fee: u128;

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

**File:** programs/cp-swap/src/instructions/swap_base_input.rs (L158-163)
```rust
    pool_state.update_fees(
        u64::try_from(result.protocol_fee).unwrap(),
        u64::try_from(result.fund_fee).unwrap(),
        u64::try_from(result.creator_fee).unwrap(),
        trade_direction,
    )?;
```

**File:** programs/cp-swap/src/states/pool.rs (L326-369)
```rust
    pub fn update_fees(
        &mut self,
        protocol_fee: u64,
        fund_fee: u64,
        creator_fee: u64,
        direction: TradeDirection,
    ) -> Result<()> {
        if !self.enable_creator_fee {
            require_eq!(creator_fee, 0)
        }
        let is_creator_fee_on_input = self.is_creator_fee_on_input(direction)?;
        match direction {
            TradeDirection::ZeroForOne => {
                self.protocol_fees_token_0 = self
                    .protocol_fees_token_0
                    .checked_add(protocol_fee)
                    .unwrap();
                self.fund_fees_token_0 = self.fund_fees_token_0.checked_add(fund_fee).unwrap();

                if is_creator_fee_on_input {
                    self.creator_fees_token_0 =
                        self.creator_fees_token_0.checked_add(creator_fee).unwrap();
                } else {
                    self.creator_fees_token_1 =
                        self.creator_fees_token_1.checked_add(creator_fee).unwrap();
                }
            }
            TradeDirection::OneForZero => {
                self.protocol_fees_token_1 = self
                    .protocol_fees_token_1
                    .checked_add(protocol_fee)
                    .unwrap();
                self.fund_fees_token_1 = self.fund_fees_token_1.checked_add(fund_fee).unwrap();
                if is_creator_fee_on_input {
                    self.creator_fees_token_1 =
                        self.creator_fees_token_1.checked_add(creator_fee).unwrap();
                } else {
                    self.creator_fees_token_0 =
                        self.creator_fees_token_0.checked_add(creator_fee).unwrap();
                }
            }
        };
        Ok(())
    }
```
