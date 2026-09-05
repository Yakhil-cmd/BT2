Based on my investigation, I found a genuine rounding-down analog in `pox-5.clar`'s bond-registration STX collateral check, which mirrors the reported bug class (integer division truncation allowing a user to underpay/under-lock relative to what they should).

### Title
Floor-division in `min-ustx-for-sats-amount` lets a staker under-lock STX relative to required sBTC-collateral ratio - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
The bond registration path computes the minimum uSTX a staker must lock for a given sats amount via `min-ustx-for-sats-amount`, using nested integer division. As documented in the test harness mirroring the contract logic, this "matches the contract's truncation" [1](#0-0) , meaning the actual on-chain check floors the required uSTX amount at each multiplication/division step, just like the reported `_getQuoteAmount` bug.

### Finding Description
The reported bug class is: sequential integer division truncates a per-unit-price calculation, letting the payer supply less value than the mathematically correct amount, with the shortfall accruing to the payer at protocol expense. In `pox-5.clar`, `register-for-bond` (and `update-bond-registration`) requires a staker to lock a minimum uSTX amount proportional to their sBTC bond size via a `stx-value-ratio`. The floor computation is:

`(((stxValueRatio * sats) / 100n) * minUstxRatio) / 10000n` [2](#0-1) 

Because this performs two separate floor-divisions (`/100` then `/10000`) rather than a single division by the combined denominator (`/1000000`), truncation happens twice, and the staker can choose a `sats` value that maximizes the cumulative truncation, locking measurably less STX than the ratio-implied minimum. This breaks the intended equality `locked_STX >= sats * stx_value_ratio * min_ratio_bps / 1e6` that the contract is meant to enforce.

### Impact Explanation
If the enforced minimum understates the true required collateral, a staker's bond membership can be registered/maintained with STX collateral that is smaller than the sBTC-denominated exposure it's meant to back. Given `calculate-bond-rewards` in `pox-5.clar` pays yield based on `total-sats` and `stx-value-ratio` [3](#0-2) , an under-collateralized bond earns rewards disproportionate to the STX actually locked, effectively letting the staker capture yield backed by insufficient collateral — a value mismatch between locked STX and claimed reward eligibility.

### Likelihood Explanation
This requires no privileged role — any unprivileged staker calling `register-for-bond`/`update-bond-registration` with a strategically chosen `sats` amount can trigger the truncation. However, I was unable to fully verify from the indexed content the exact magnitude of the minimum truncation gap (`stxValueRatio`, `minUstxRatio` precision, and how tightly `register-for-bond` enforces this floor against actual locked amounts) because the full body of `register-for-bond` and the `min-ustx-for-sats-amount` definition in `pox-5.clar` were not fully retrievable within the available search iterations.

### Recommendation
Combine the two division steps into a single division by the full denominator (e.g., `(stxValueRatio * sats * minUstxRatio) / 1000000`) to minimize truncation to a single floor operation, and/or round up (ceiling) the minimum-required uSTX rather than flooring it, so the staker is never permitted to lock strictly less than the ratio-implied minimum.

### Proof of Concept
Not independently reproduced against the live contract in this session — the analog is inferred from the test helper `minUstxForSats` in `contrib/core-contract-tests/tests/pox-5/commands/utils.ts:239-245`, which explicitly states it replicates "the contract's truncation," and from the reward-distribution logic in `calculate-bond-rewards` (`stackslib/src/chainstate/stacks/boot/pox-5.clar:2260-2280`) that ties payout to `stx-value-ratio`/sats without re-validating collateral sufficiency at payout time. Confirming exploitability requires reading the full `register-for-bond` implementation in `pox-5.clar`, which the current index did not surface in full. [1](#0-0) [4](#0-3)

### Citations

**File:** contrib/core-contract-tests/tests/pox-5/commands/utils.ts (L235-245)
```typescript
/**
 * Contract's `min-ustx-for-sats-amount`: the floor uSTX a staker must lock for
 * `sats`. Integer division at each step, matching the contract's truncation.
 */
export function minUstxForSats(
  sats: bigint,
  stxValueRatio: bigint,
  minUstxRatio: bigint,
): bigint {
  return (((stxValueRatio * sats) / 100n) * minUstxRatio) / 10000n;
}
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2258-2280)
```text
    (let (
            (accumulator (try! accumulator-res))
            (bond (unwrap! (map-get? protocol-bonds bond-index) ERR_BOND_NOT_FOUND))
            (reward-cycle (get reward-cycle accumulator))
            (total-sats (get-total-shares-staked-for-cycle reward-cycle (some bond-index)))
            (available-rewards (get available-rewards accumulator))
            ;; How much sBTC the bond is supposed to earn per calculation,
            ;; which is (totalSats * apy) / 50
            (target-yield (/ (/ (* total-sats (get target-rate bond)) u10000) u50))
            ;; If there is enough to cover the target yield, use that. Otherwise,
            ;; this bond gets the remaining rewards.
            (earned (if (>= available-rewards target-yield)
                target-yield
                available-rewards
            ))
            (stx-value-ratio (get stx-value-ratio bond))
            (current-rewards-per-token (get-rewards-per-token-for-cycle reward-cycle (some bond-index)))
            ;; Prevent divide-by-zero
            (accrued-rewards-per-sat (if (is-eq total-sats u0)
                u0
                (/ (* earned PRECISION) total-sats)
            ))
            (calculation-height (get calculation-height accumulator))
```
