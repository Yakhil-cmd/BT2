### Title
Missing Zero-Check for `strk_total_stake` in `calculate_staker_total_staking_power` Causes `get_stakers` to Panic - (File: src/staking/utils.cairo)

---

### Summary

`calculate_staker_total_staking_power` in `src/staking/utils.cairo` divides by `strk_total_stake` without a zero-guard, while the analogous BTC branch has an explicit zero-check. When all stakers have called `unstake_intent` (removing their stake from the total-stake trace) but have not yet called `unstake_action`, `strk_total_stake` becomes 0 while stakers remain in the `stakers` vector and are still considered active for the current epoch window. Any call to `get_stakers` in that window will reach the unguarded division and panic, making the consensus staker-list endpoint permanently unavailable until the state resolves.

---

### Finding Description

In `src/staking/utils.cairo` lines 130–135, the STRK staking-power component is computed as:

```cairo
let strk_staking_power = mul_wide_and_div(
    lhs: staker_strk_total_amount.to_amount_18_decimals(),
    rhs: STRK_WEIGHT_FACTOR,
    div: strk_total_stake.to_amount_18_decimals(),   // ← no zero-check
)
    .unwrap();
``` [1](#0-0) 

Immediately below, the BTC branch guards against the same condition:

```cairo
let btc_staking_power = if btc_total_stake.is_zero() {
    Zero::zero()
} else {
    mul_wide_and_div(...).unwrap()
};
``` [2](#0-1) 

The asymmetry is the root cause. `mul_wide_and_div` returns `Option::None` when the divisor is 0; `.unwrap()` then panics.

**How `strk_total_stake` reaches 0 while active stakers exist:**

`unstake_intent` removes both own-stake and delegated-stake from `tokens_total_stake_trace` immediately:

```cairo
self.remove_from_total_stake(token_address: STRK_TOKEN_ADDRESS, amount: old_self_stake);
``` [3](#0-2) 

But the staker's *intent epoch* is written as `current_epoch + K` (K = 2):

```cairo
self.staker_unstake_intent_epoch.write(staker_address, self.get_epoch_plus_k());
``` [4](#0-3) 

`get_stakers` is restricted to `epoch_id ∈ [curr_epoch, curr_epoch + K)`:

```cairo
assert!(
    curr_epoch <= epoch_id && epoch_id < curr_epoch + K.into(),
    "{}",
    Error::INVALID_EPOCH,
);
``` [5](#0-4) 

For the two epochs between `unstake_intent` and the intent's effective epoch, stakers are still considered active (their `staker_unstake_intent_epoch` has not yet been reached), yet their stake has already been subtracted from the total. If every staker calls `unstake_intent` in the same epoch, `strk_total_stake` drops to 0 while `is_staker_active` still returns `true` for all of them, triggering the unguarded division.

---

### Impact Explanation

`get_stakers` is the entry point used by the off-chain consensus layer to obtain the validator set and staking-power weights for a given epoch:

```cairo
fn get_stakers(
    self: @ContractState, epoch_id: Epoch,
) -> Span<(ContractAddress, StakingPower, Option<PublicKey>, Option<PeerId>)>
``` [6](#0-5) 

A panic here makes the validator-set query unavailable for up to K epochs. Because consensus-based reward distribution depends on this data, no block rewards can be calculated or distributed during that window — matching the **High: Temporary freezing of unclaimed yield** impact category.

---

### Likelihood Explanation

The trigger condition — all active stakers calling `unstake_intent` within the same epoch — is realistic during a coordinated wind-down, a governance-driven migration, or a market event that causes mass exit. It requires no privileged access; any staker can call `unstake_intent` permissionlessly. The K = 2 epoch window during which the bug is exploitable is narrow but deterministic and predictable.

---

### Recommendation

Add the same zero-guard to the STRK branch that already exists for BTC:

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

This mirrors the existing BTC guard at lines 136–145 of `src/staking/utils.cairo` and eliminates the division-by-zero path.

---

### Proof of Concept

1. All N stakers call `unstake_intent` in epoch E.
   - Each call executes `remove_from_total_stake(STRK_TOKEN_ADDRESS, ...)`, driving `strk_total_stake` to 0.
   - Each staker's `staker_unstake_intent_epoch` is set to E + 2.
2. In epoch E or E + 1, any caller invokes `get_stakers(epoch_id: E)` (or `E + 1`).
3. `get_total_staking_power_at_epoch` returns `strk_total_stake = 0`.
4. The loop reaches a staker for which `is_staker_active` returns `true` (intent epoch not yet reached).
5. `get_staker_staking_power_at_epoch` → `calculate_staker_total_staking_power` is called with `strk_total_stake = 0`.
6. `mul_wide_and_div(..., div: 0)` returns `None`; `.unwrap()` panics.
7. `get_stakers` reverts; the consensus layer cannot obtain the validator set for epochs E and E + 1.

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

**File:** src/staking/staking.cairo (L446-446)
```text
            self.staker_unstake_intent_epoch.write(staker_address, self.get_epoch_plus_k());
```

**File:** src/staking/staking.cairo (L467-468)
```text
            let old_self_stake = self.get_own_balance(:staker_address);
            self.remove_from_total_stake(token_address: STRK_TOKEN_ADDRESS, amount: old_self_stake);
```

**File:** src/staking/staking.cairo (L901-903)
```text
        fn get_stakers(
            self: @ContractState, epoch_id: Epoch,
        ) -> Span<(ContractAddress, StakingPower, Option<PublicKey>, Option<PeerId>)> {
```

**File:** src/staking/staking.cairo (L905-909)
```text
            assert!(
                curr_epoch <= epoch_id && epoch_id < curr_epoch + K.into(),
                "{}",
                Error::INVALID_EPOCH,
            );
```
