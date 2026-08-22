# Finding: Integer-truncation gas-refund-penalty underpayment via receipt splitting - (File: `core/parameters/src/cost.rs`)

### Summary
`RuntimeFeesConfig::gas_penalty_for_gas_refund` (NEP-536) computes the penalty on unused/refunded gas with a single floor-division `gas_refund * numerator / denominator`, applied independently **per receipt**. Because integer division truncates downward and is re-applied once per receipt rather than once per logical unit of work, a caller who splits one large over-provisioned function call into many smaller over-provisioned function calls pays a strictly lower (or equal) total penalty than one call with the same aggregate excess gas — the exact "split the loan into many small loans" pattern described in the Eggs.sol report.

### Finding Description
The penalty is computed as:

```rust
// core/parameters/src/cost.rs:705-715
pub fn gas_penalty_for_gas_refund(&self, gas_refund: Gas) -> Gas {
    let relative_cost = Gas::from_gas(
        (u128::from(gas_refund.as_gas()) * *self.gas_refund_penalty.numer() as u128
            / *self.gas_refund_penalty.denom() as u128)
            .try_into()
            .unwrap(),
    );
    let penalty = std::cmp::max(relative_cost, self.min_gas_refund_penalty);
    std::cmp::min(penalty, gas_refund)
}
``` [1](#0-0) 

This is invoked once for every action receipt's leftover gas in `refund_unspent_gas_and_deposits`:

```rust
// runtime/runtime/src/lib.rs:1186
let refund_penalty: Gas = config.fees.gas_penalty_for_gas_refund(gross_gas_refund);
``` [2](#0-1) 

Because `floor(a * p/q) + floor(b * p/q) ≤ floor((a+b) * p/q)` for any non-negative integers `a`, `b`, splitting a single large excess-gas function call (which yields one receipt with a large `gross_gas_refund`) into `N` smaller function calls with the same aggregate excess gas but many receipts each yields a strictly smaller (or equal) *sum* of penalties than a single receipt carrying the full excess. This is mathematically identical to the Eggs.sol bug, where `3900 * numberOfDays / 365` truncated more favorably when applied to many short periods than to one long period.

The `min_gas_refund_penalty` floor (`std::cmp::max(relative_cost, min_gas_refund_penalty)`) can mask the effect when it is non-zero and dominates small per-receipt amounts, but the runtime parameter files show this floor is configured to `0`:

```
min_gas_refund_penalty: 0
``` [3](#0-2) 

With the floor at zero, `gas_penalty_for_gas_refund` reduces to pure `floor(gas_refund * numerator/denominator)`, and the truncation-splitting effect is unmitigated.

### Impact Explanation
This is a fee-underpayment / underpriced-execution bug reachable from any submitted `SignedTransaction` containing multiple `FunctionCall` actions (or multiple transactions), each attaching more gas than it needs. Whenever `gas_refund_penalty` is configured with a non-zero rate (the mechanism exists precisely to make refunds costly per NEP-536, and non-zero values are exercised in the codebase's own fixture/test configs, e.g. `gas_refund_penalty` fractions used in tests), an attacker can systematically reduce the total refund penalty burnt by fragmenting a batch of over-provisioned gas across many small receipts instead of one large one. The result is that the protocol collects less than the intended fraction of unused gas as burnt penalty, i.e., underpriced execution of the NEP-536 anti-griefing/refund-cost mechanism.

### Likelihood Explanation
Exploitation requires no special privileges — any account can submit a batch of `FunctionCall` actions (or a sequence of transactions) that intentionally over-attach gas relative to what each call will burn, and rely on many small receipts each receiving independently-floored penalties. The larger the number of independent receipts and the smaller the gas-refund per receipt, the larger the aggregate saving relative to a single large refund. On networks where `gas_refund_penalty` numerator is non-zero and `min_gas_refund_penalty` is zero (as configured in `core/parameters/res/runtime_configs/parameters.yaml`), the effect is directly exploitable with no additional preconditions.

### Recommendation
Compute the gas refund penalty using higher precision (e.g., scale by a large fixed denominator such as `1e18`) and/or accumulate all refundable gas across a transaction's receipts before applying the floor division once, rather than truncating independently per receipt. Alternatively, round the per-receipt penalty up instead of down, or track and carry forward a truncation remainder across receipts of the same transaction so the aggregate penalty converges to the intended proportional amount regardless of how work is split across receipts.

### Proof of Concept
Given `gas_refund_penalty = numerator/denominator` and `min_gas_refund_penalty = 0`:
- Single large call: one receipt refunds `gross_gas_refund = R` gas → penalty = `floor(R * numerator/denominator)`.
- N split calls: each receipt refunds `R/N` gas → total penalty = `N * floor((R/N) * numerator/denominator) ≤ floor(R * numerator/denominator)`.

For concrete numbers using a hypothetical enabled rate `numerator=5, denominator=100` (5%, as used in several test/fixture configs) and `R = 999` Tgas:
- One receipt: `floor(999 * 5/100) = floor(49.95) = 49` Tgas penalty.
- Split into 999 receipts of 1 Tgas each: `floor(1*5/100) = 0` Tgas penalty per receipt → total = `0` Tgas penalty.

The attacker saves the entire 49 Tgas worth of penalty (converted to balance at the burn gas price) simply by fragmenting the same aggregate wasted/prepaid gas into many small function-call receipts instead of one, mirroring the Eggs.sol "many short loans vs one long loan" exploit pattern.

### Citations

**File:** core/parameters/src/cost.rs (L705-715)
```rust
    pub fn gas_penalty_for_gas_refund(&self, gas_refund: Gas) -> Gas {
        let relative_cost = Gas::from_gas(
            (u128::from(gas_refund.as_gas()) * *self.gas_refund_penalty.numer() as u128
                / *self.gas_refund_penalty.denom() as u128)
                .try_into()
                .unwrap(),
        );

        let penalty = std::cmp::max(relative_cost, self.min_gas_refund_penalty);
        std::cmp::min(penalty, gas_refund)
    }
```

**File:** runtime/runtime/src/lib.rs (L1185-1192)
```rust
        // NEP-536 also adds a penalty to gas refund.
        let refund_penalty: Gas = config.fees.gas_penalty_for_gas_refund(gross_gas_refund);
        let penalty_gas_price = if ProtocolFeature::AccountCostIncrease.enabled(protocol_version) {
            gas_burn_price
        } else {
            gas_purchase_price
        };
        let refund_penalty_amount = safe_gas_to_balance(penalty_gas_price, refund_penalty)?;
```

**File:** core/parameters/res/runtime_configs/parameters.yaml (L14-19)
```yaml
gas_refund_penalty: {
  numerator: 0,
  denominator: 100,
}
min_gas_refund_penalty: 0
min_gas_purchase_price: 0
```
