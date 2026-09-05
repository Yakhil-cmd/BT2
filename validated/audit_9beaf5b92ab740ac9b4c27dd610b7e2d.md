## Analog Found

### Title
Integer-division truncation in `min-ustx-for-sats-amount` lets stakers bypass the STX collateral requirement for bond registration - (File: `stackslib/src/chainstate/stacks/boot/pox-5.clar`)

### Summary
The WooFi report describes a class of bug where chained integer divisions cause a computed price/threshold to round down to `0`, which is then misread by a downstream equality/bound check as "no requirement," silently bypassing validation. `pox-5.clar`'s `min-ustx-for-sats-amount` performs the analogous chained-division pattern, and its result gates the only check that ties a bond staker's locked STX to the amount of sats they custody.

### Finding Description
`min-ustx-for-sats-amount` computes the minimum uSTX a staker must lock for a given sats amount using two nested integer divisions: [1](#0-0) 

```
(/ (* (/ (* stx-value-ratio sats-amount) u100) min-ustx-ratio) u10000)
```

This mirrors the WooFi pattern exactly: `refPrice = (baseRefPrice * ceoff) / quoteRefPrice`, where a legitimate combination of small numerator / large denominator terms can floor the result to `0`. Here, whenever `floor(stx-value-ratio * sats-amount / 100) * min-ustx-ratio < 10000`, the function returns `u0`, regardless of how many sats are being staked.

This value is the *only* gate enforcing that a staker puts up STX collateral proportional to the sats/BTC they're locking into a protocol bond: [2](#0-1) 

```
(asserts!
    (>= amount-ustx
        (min-ustx-for-sats-amount sats-total (get stx-value-ratio bond)
            (get min-ustx-ratio bond)
        ))
    ERR_INSUFFICIENT_STX
)
```

If `min-ustx-for-sats-amount` returns `u0` (due to the rounding described above, triggered by a bond configured with a low `stx-value-ratio` and/or low `min-ustx-ratio` — both legitimate admin-set parameters, not attacker-controlled inputs), then `amount-ustx = u0` trivially satisfies `>= u0`. The staker can register for the bond, custody sats/BTC up to their allowance, and be admitted to `protocol-bond-memberships` with **zero real STX locked**.

Critically, the staker's `sats-total` (not `amount-ustx`) is what counts toward `protocol-bonds-total-staked` and `get-total-shares-staked-for-cycle`, which directly drives the bond's sBTC reward accrual in `calculate-bond-rewards`: [3](#0-2) 

So the staker earns the bond's full sBTC yield on their sats, occupying a bond reward slot that was intended to require proportional STX collateral, while providing none of the required STX value — an equality (`amount-ustx >= f(sats-total)`) that the protocol is designed to always enforce is silently violated by rounding.

### Impact Explanation
This breaks the "signing weight or reward slots exceeding locked value" invariant: a bond registration slot is granted, and sBTC rewards are earned against the custodied sats, without the STX collateral requirement (`min-ustx-for-sats-amount`) actually being met. This is a design-level violation caused purely by the two chained integer divisions used to compute the floor amount, not by any admin/attacker misconfiguration outside the bond's own legitimate parameter space (`stx-value-ratio`, `min-ustx-ratio`), matching the analog bug class exactly.

### Likelihood Explanation
The bug is triggered whenever `floor(stx-value-ratio * sats-amount / 100) * min-ustx-ratio < 10000`. This is easily reachable for bonds configured with a low `min-ustx-ratio` (a legitimate, valid basis-point value near the low end of the allowed range) combined with realistic sats amounts, or for bonds with a low `stx-value-ratio`. No special privileges are needed — any allow-listed staker calling `register-for-bond` with `amount-ustx = 0` (or any value below the true intended minimum) can exploit this whenever the bond's configured ratios cause the computed floor to round to zero.

### Recommendation
Increase the precision of `min-ustx-for-sats-amount`'s intermediate computation (e.g., avoid the intermediate `/ u100` truncation by reordering multiplications before divisions, or use a higher-precision fixed-point scale similar to `PRECISION` used elsewhere in the contract), and/or explicitly reject a computed minimum of `u0` when `sats-total > 0`, so that the size of `stx-value-ratio` or `min-ustx-ratio` can never fully collapse the STX collateral requirement.

### Proof of Concept
1. Admin creates a protocol bond via `setup-bond` with `min-ustx-ratio` set low (e.g. `u1`, 0.01%) and a `stx-value-ratio` such that `floor(stx-value-ratio * sats-amount / 100) * 1 < 10000` for the sats amount the staker intends to lock (e.g. `stx-value-ratio = u1000`, `sats-amount = u900000` → `floor(1000*900000/100)=9,000,000`; choose smaller sats or ratio so the product stays under `10000`, e.g. `stx-value-ratio=u1`, `sats-amount=u9999` → `floor(9999/100)=99`, `99*1=99 < 10000` → `min-ustx-for-sats-amount` returns `u0`).
2. Attacker (already allow-listed for the bond) calls `register-for-bond` with `amount-ustx = u0` and `btc-lockup` = `(err sats-amount)` for the chosen `sats-amount`.
3. The check `(>= u0 u0)` passes, `ERR_INSUFFICIENT_STX` is never raised.
4. The staker's `sats-total` is added to `protocol-bonds-total-staked` and counted in `get-total-shares-staked-for-cycle`, entitling them to a proportional share of the bond's sBTC rewards from `calculate-bond-rewards`, despite having locked `u0` STX.

### Citations

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L712-719)
```text
        ;; Verify that they're sending enough STX
        (asserts!
            (>= amount-ustx
                (min-ustx-for-sats-amount sats-total (get stx-value-ratio bond)
                    (get min-ustx-ratio bond)
                ))
            ERR_INSUFFICIENT_STX
        )
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2262-2279)
```text
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
```

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L3089-3095)
```text
(define-read-only (min-ustx-for-sats-amount
        (sats-amount uint)
        (stx-value-ratio uint)
        (min-ustx-ratio uint)
    )
    (/ (* (/ (* stx-value-ratio sats-amount) u100) min-ustx-ratio) u10000)
)
```
