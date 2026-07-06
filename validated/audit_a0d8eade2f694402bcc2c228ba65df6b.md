### Title
Division by Zero in `calculate_staker_total_staking_power` When `strk_total_stake` Is Zero — (`src/staking/utils.cairo`)

---

### Summary

`calculate_staker_total_staking_power` in `src/staking/utils.cairo` unconditionally divides by `strk_total_stake` without a zero guard. The analogous BTC branch in the same function explicitly handles the zero case, but the STRK branch does not. When `strk_total_stake` is zero the function panics, blocking any reward-calculation path that calls it. The test suite itself documents this risk with an explicit comment.

---

### Finding Description

In `src/staking/utils.cairo`, `calculate_staker_total_staking_power` computes two per-token staking-power contributions and sums them:

```cairo
// STRK branch — NO zero guard
let strk_staking_power = mul_wide_and_div(
    lhs: staker_strk_total_amount.to_amount_18_decimals(),
    rhs: STRK_WEIGHT_FACTOR,
    div: strk_total_stake.to_amount_18_decimals(),   // ← divisor, never checked
)
    .unwrap();
``` [1](#0-0) 

```cairo
// BTC branch — zero guard present
let btc_staking_power = if btc_total_stake.is_zero() {
    Zero::zero()
} else {
    mul_wide_and_div(
        lhs: staker_btc_total_amount.to_amount_18_decimals(),
        rhs: BTC_WEIGHT_FACTOR,
        div: btc_total_stake.to_amount_18_decimals(),
    )
        .unwrap()
};
``` [2](#0-1) 

The BTC branch is protected; the STRK branch is not. When `strk_total_stake == 0`, `mul_wide_and_div` performs integer division by zero and the call panics.

The test suite explicitly acknowledges this risk:

```cairo
// Advance k epochs to ensure the total stake in the current epoch is nonzero, preventing a
// division by zero when calculating rewards.
advance_k_epochs_global();
``` [3](#0-2) 

The workaround used in tests (advancing K epochs) is not enforced on-chain, leaving the production path unguarded.

---

### Impact Explanation

Any on-chain call that reaches `calculate_staker_total_staking_power` while `strk_total_stake` is zero will panic and revert. This blocks reward distribution for all stakers and delegators for as long as the condition persists, constituting **temporary (potentially permanent) freezing of unclaimed yield**.

---

### Likelihood Explanation

Two realistic scenarios produce `strk_total_stake == 0`:

1. **Protocol bootstrap / first K epochs** — The balance-trace system records stake with a K-epoch delay. Immediately after the first staker stakes (or after a protocol upgrade), the "current epoch" total stake read by the reward path is zero for up to K epochs. Any attestation or `update_rewards` call during this window hits the division.

2. **All STRK stakers exit** — If every STRK staker completes the two-step unstake process, `strk_total_stake` drops to zero. A subsequent reward-cycle trigger (by any public caller) then panics.

Neither scenario requires a privileged role; a regular staker, delegator, or any public caller can trigger the path.

---

### Recommendation

Mirror the BTC zero-guard pattern for the STRK branch:

```cairo
let strk_staking_power = if strk_total_stake.is_zero() {
    Zero::zero()
} else {
    mul_wide_and_div(
        lhs: staker_strk_total_amount.to_amount_18_decimals(),
        rhs: STRK_WEIGHT_FACTOR,
        div: strk_total_stake.to_amount_18_decimals(),
    )
        .unwrap()
};
```

This is consistent with how the BTC case is already handled and eliminates the panic without changing the intended reward semantics (a staker with zero STRK stake contributes zero STRK staking power).

---

### Proof of Concept

1. Deploy the protocol (or advance to a state where all STRK stakers have exited).
2. Confirm `staking.get_current_total_staking_power()` returns `(0, _)` for the STRK component.
3. Call any public function that internally invokes `calculate_staker_total_staking_power` (e.g., `update_rewards` or `attest`).
4. Observe the transaction reverts with a division-by-zero panic, blocking reward distribution.

The test comment at `src/staking/tests/test.cairo:615–617` already documents that skipping the K-epoch advance reproduces this panic, confirming the root cause.

### Citations

**File:** src/staking/utils.cairo (L130-135)
```text
    let strk_staking_power = mul_wide_and_div(
        lhs: staker_strk_total_amount.to_amount_18_decimals(),
        rhs: STRK_WEIGHT_FACTOR,
        div: strk_total_stake.to_amount_18_decimals(),
    )
        .unwrap();
```

**File:** src/staking/utils.cairo (L136-145)
```text
    let btc_staking_power = if btc_total_stake.is_zero() {
        Zero::zero()
    } else {
        mul_wide_and_div(
            lhs: staker_btc_total_amount.to_amount_18_decimals(),
            rhs: BTC_WEIGHT_FACTOR,
            div: btc_total_stake.to_amount_18_decimals(),
        )
            .unwrap()
    };
```

**File:** src/staking/tests/test.cairo (L615-617)
```text
    // Advance k epochs to ensure the total stake in the current epoch is nonzero, preventing a
    // division by zero when calculating rewards.
    advance_k_epochs_global();
```
