### Title
Dust-sized liquidation repayments zero out the protocol fee via the whole-unit realised-excess cap - (File: contracts/controller/src/positions/liquidation/math.rs)

### Summary
The protocol's liquidation fee is charged only on whole-token units of realised excess (`paid_ray - base_ray`). When the pool's gross payout above the leg's principal is smaller than one token unit, `realised_excess` floors to zero and `protocol_fee` becomes zero even though the planned fee (`fee_ray`) is positive. An unprivileged liquidator — including the borrower self-liquidating (INV-LIQ-01 explicitly allows self-liquidation) — controls the repayment size, so they can repeatedly submit repayments small enough that each leg's excess payout stays below one token unit, extracting the liquidation bonus while paying no protocol fee at all. This is the same class as the reference finding: under-sized settlement lets the counterparty skip fees that the protocol intends to charge.

### Finding Description
In `calculate_seized_collateral`, the planned fee is `protocol_fee_ray = liquidation_fees.apply_to_ray(bonus_ray)` on the uncapped bonus (`math.rs:443`). For `SeizeMode::Transfer` the token fee is `bumped_fee = max(1, floor(fee_ray))` when positive (`math.rs:476-481`), but it is then clamped by `realised_excess`, the whole-unit floor of `paid_ray - base_ray` (`math.rs:482-490`):

```rust
let realised_excess = if paid_ray > base_ray {
    paid_ray.checked_sub(env, base_ray).to_asset_floor(env, feed.asset_decimals)
} else { 0 };
let protocol_fee = bumped_fee.min(realised_excess);
```

`paid_ray` is the pool's gross payout for the floored seizure amount (`resolve_withdrawal` on `capped_amount`, `math.rs:469-475`). `base_ray` derives from the *uncapped* seizure (`math.rs:436`), so whenever the seized bonus portion is worth less than one base unit of the collateral token, `realised_excess == 0` and `protocol_fee == 0` while `bonus_ray > 0` and the liquidator still receives the sub-unit excess in the token transfer.

The repayment amount — and therefore the per-leg seizure and excess — is liquidator-chosen: `liquidate` accepts any payment up to the curve quote (`normalize_repayment_plan`, `math.rs:173-224`), partial plans are not trimmed below the quote, and there is no minimum-repayment or minimum-fee check on execution. A liquidation can thus be split into arbitrarily many small repayments, each producing `0 < paid - base < 1` unit, so every leg pays zero fee. The invariant "a seizure clamped at or below the repayment share is a bad-debt close: no fee" (certora spec comment) covers `capped_ray <= base_ray`, but does not cover `capped_ray > base_ray` with a sub-unit token excess, which is what this path allows.

### Impact Explanation
Direct, repeatable loss of protocol liquidation-fee revenue. Any unprivileged address can liquidate (or self-liquidate to avoid paying fees to third-party liquidators) in small chunks so the protocol's configured `liquidation_fees` bps are never collected in Transfer mode, while the liquidator keeps the full bonus. On low-decimal or high-value-per-unit collateral the dodge window is larger; on 7-decimal assets it requires keeping each leg's bonus payout under ~$0.1–$1 depending on price, which is trivially achievable by sizing repayments. Per the accepted-impact rules this is theft of protocol fees / unclaimed revenue attributable to rounding — a Medium-severity analog of the reported "closure that does not result in fee payout".

### Likelihood Explanation
No special privileges, timing, or oracle manipulation are needed: the caller just calls `liquidate` with a small `HubPayment` vector. Any account below HF = 1 can be sliced this way indefinitely until collateral or debt is exhausted, and the gas/computation cost per slice is the only limit. The only mitigation is that the protocol fee floor (`bumped_fee` minimum of one unit) was designed to round *up* dust fees, but the `realised_excess` cap silently reverses that to zero precisely in the dust regime, so the countermeasure intended for this edge case does not fire.

### Recommendation
When `protocol_fee_ray > 0` and `paid_ray > base_ray` but the excess is sub-unit, charge one token unit (i.e. `protocol_fee = bumped_fee.min(paid_asset_units_above_base.ceil())`) or take the sub-unit excess in shares/Credit reclassification rather than dropping the fee to zero. Alternatively reject plans whose per-leg bonus payout is below one token unit (`InvalidPayments`), mirroring the reference fix that reverts a closure which does not pay fees. Credit mode already uses `ceil(bonus_scaled * fee_bps / BPS)` in `split_seized_shares` (`math.rs:547`) and does not have this hole; Transfer mode should apply an equivalent ceiling to the realised excess instead of `to_asset_floor`.

### Proof of Concept
1. Victim account: single collateral leg, asset `A` (e.g. 7-decimal XLM at $0.25), debt leg `B`, HF < 1, `liquidation_fees = 1200` bps, bonus `b` from the curve.
2. Liquidator calls `get_liquidation_estimate` and picks a repayment `x` such that the seizure `x·(1+b)/price_A` exceeds the principal `x/price_A` by less than 1 stroop of `A` (e.g. `x·b/WAD < 1e-7 A`), and submits `liquidate(account, [{hub, B, x}], SeizeMode::Transfer)`.
3. In `calculate_seized_collateral`: `bonus_ray > 0`, `protocol_fee_ray > 0`, `bumped_fee = 1`, but `paid_ray - base_ray < 1` unit → `realised_excess = 0` → `protocol_fee = 0`. The `SeizeEntry` carries a positive `bonus_scaled` with zero fee, and the pool transfers the full excess to the liquidator.
4. Repeat until the account is fully closed. Total protocol fee collected: 0, versus `fees_bps` of the aggregate bonus under a single-shot liquidation. No privileged role or price manipulation is used at any step.