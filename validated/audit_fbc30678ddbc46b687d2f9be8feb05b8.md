### Title
Truncated two-stage integer division in `min-ustx-for-sats-amount` lets a staker register a protocol bond with near-zero locked STX for real sBTC/L1 sats collateral - ([File: stackslib/src/chainstate/stacks/boot/pox-5.clar])

### Summary
`min-ustx-for-sats-amount` computes the STX collateral floor a staker must lock in order to register for a protocol bond backed by a given amount of sats. The formula performs two sequential truncating divisions, so for small enough `sats-amount` (relative to `stx-value-ratio`/`min-ustx-ratio`) the function returns `u0` even though the sats amount being staked is non-zero. `register-for-bond` only asserts `amount-ustx >= (min-ustx-for-sats-amount ...)`, so when the floor rounds to zero the staker can satisfy the check with a trivial `amount-ustx` while still custodying/locking a real, non-zero sats amount for bond membership and bond-reward eligibility.

### Finding Description
`min-ustx-for-sats-amount` is defined as: [1](#0-0) 

The computation is `(/ (* (/ (* stx-value-ratio sats-amount) u100) min-ustx-ratio) u10000)`. Because the inner term `(/ (* stx-value-ratio sats-amount) u100)` truncates toward zero, whenever `stx-value-ratio * sats-amount < 100` the intermediate value is `0`, and the whole expression evaluates to `0` regardless of `min-ustx-ratio`. The outer division can independently truncate to `0` as well when the (non-zero) intermediate value times `min-ustx-ratio` is `< 10000`.

`register-for-bond` uses this value as the sole gate on the STX a staker must commit relative to the sats they are staking: [2](#0-1) 

The sats amount used in this check, `sats-total`, is derived from a real sBTC transfer or a verified L1 Bitcoin lockup proof (`verify-l1-lockups`) and is used unmodified everywhere bond rewards are computed - `calculate-bond-rewards` distributes yield strictly as a function of `total-sats`, not `amount-ustx`: [3](#0-2) 

This mirrors the ACO analog exactly: the same style of chained-division "cost" function is used to gate an input (here, the STX a staker must lock as collateral/insurance for a bond) while the "value" side of the transaction (the sats a bond earns rewards on) is computed independently and is not subject to the same rounding. When the gating computation rounds down to zero, the staker satisfies the floor with a negligible `amount-ustx`, while the sats-based reward eligibility is unaffected.

The only remaining backstop is the node-level lock, which merely rejects `amount-ustx == 0` (not a meaningful floor): [4](#0-3) 

### Impact Explanation
`min-ustx-for-sats-amount`'s intended purpose (per its own doc comment) is to make sure a staker locks an STX amount proportional to the sats being staked in a bond, which is the STX-side "skin in the game"/insurance for the bond. If the floor rounds to zero, a staker can obtain full bond membership and bond-reward eligibility (rewards distributed strictly by `total-sats`, see `calculate-bond-rewards`) while contributing only a token (as low as `u1`) amount of locked STX rather than the ratio-implied amount. This is a case of reward-slot/collateral-backing exceeding the locked STX value that was supposed to back it, matching the "signing weight or reward slots exceeding locked value" High-impact category.

### Likelihood Explanation
Exploitability is bounded by the truncation math and by the bond's admin-chosen `stx-value-ratio`/`min-ustx-ratio` parameters (set via `setup-bond`, a privileged call). The zero-floor condition `stx-value-ratio * sats-amount < 100` (plus the second-stage truncation) means the size of sats that can bypass the floor scales with the chosen ratios; for the ratios used throughout the test suite (e.g. `stxValueRatio = 10000000n`) the bypassable sats window is small, but for smaller `stx-value-ratio` configurations the bypassable sats amount grows. Whether an unprivileged staker can reach economically meaningful sats amounts depends entirely on bond parameters an admin has already configured, which I could not fully enumerate/bound within the available tool budget - I was unable to confirm whether an additional absolute uSTX floor (e.g., a `SIGNER_SET_MIN_USTX`-style check) is enforced specifically inside `register-for-bond` beyond the ratio-derived floor and the non-zero lock check, so the practical severity is uncertain without that confirmation.

### Recommendation
Round `min-ustx-for-sats-amount` up rather than down (ceiling division) at both division stages, or reorder the arithmetic to a single multiply-then-divide with ceiling rounding, so that any non-zero `sats-amount` produces a non-zero (and correctly-proportional) required `amount-ustx`. Additionally, consider enforcing an absolute minimum `amount-ustx` for any bond registration with `sats-total > 0`, independent of the ratio computation, so future ratio configurations cannot re-introduce a zero-floor edge case.

### Proof of Concept
1. Admin calls `setup-bond` with a small `stx-value-ratio` (e.g. `u1`) such that `stx-value-ratio * sats-amount < 100` is achievable for realistic sats amounts, per [1](#0-0) .
2. Staker calls `register-for-bond` with `btc-lockup` set to a real sBTC transfer (or verified L1 proof) of `sats-total` sats where `sats-total < 100 / stx-value-ratio`, and `amount-ustx = u1` (minimal non-zero to satisfy `pox_lock_v5`'s non-zero check).
3. The assertion at [2](#0-1)  passes because `min-ustx-for-sats-amount` returns `u0`.
4. The staker's bond membership is recorded with `sats-total` real sats, and future `calculate-bond-rewards` calls at [3](#0-2)  pay bond yield proportional to `sats-total`, while only `u1` microstacks was ever locked as STX collateral.

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

**File:** stackslib/src/chainstate/stacks/boot/pox-5.clar (L2260-2266)
```text
            (bond (unwrap! (map-get? protocol-bonds bond-index) ERR_BOND_NOT_FOUND))
            (reward-cycle (get reward-cycle accumulator))
            (total-sats (get-total-shares-staked-for-cycle reward-cycle (some bond-index)))
            (available-rewards (get available-rewards accumulator))
            ;; How much sBTC the bond is supposed to earn per calculation,
            ;; which is (totalSats * apy) / 50
            (target-yield (/ (/ (* total-sats (get target-rate bond)) u10000) u50))
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

**File:** pox-locking/src/pox_5.rs (L167-172)
```rust
    if unlock_burn_height == 0 {
        return Err(LockingError::PoxInvalidUnlockHeight);
    }
    if lock_amount == 0 {
        return Err(LockingError::PoxInvalidLockAmount);
    }
```
