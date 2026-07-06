### Title
Commission Change Without Prior Reward Settlement Allows Staker to Retroactively Steal Delegator Yield - (File: `src/staking/staking.cairo`)

### Summary

When a staker calls `set_commission` to change their commission rate, the new rate is written to storage immediately with no prior settlement of the current epoch's accumulated rewards. Because rewards are only calculated and distributed at attestation time (once per epoch), the new commission applies retroactively to the **entire epoch's** rewards. A staker who holds an active `CommissionCommitment` can exploit this to increase their commission to `max_commission` just before attesting, stealing the full epoch's pool rewards from delegators.

---

### Finding Description

`set_commission` in `src/staking/staking.cairo` updates the commission in storage and emits an event, but performs no reward settlement:

```cairo
fn set_commission(ref self: ContractState, commission: Commission) {
    self.general_prerequisites();
    ...
    let staker_pool_info = self.staker_pool_info.entry(staker_address);
    if let Option::Some(old_commission) = staker_pool_info.commission.read() {
        self.update_commission(:staker_address, :staker_pool_info, :old_commission, :commission);
    } else { ... }
}
``` [1](#0-0) 

The internal `update_commission` function also only writes the new value and emits an event — no reward distribution occurs:

```cairo
// Update commission in storage.
staker_pool_info.commission.write(Option::Some(commission));
``` [2](#0-1) 

When rewards are eventually calculated at attestation time, `calculate_staker_pools_rewards` reads the **current** commission from storage and applies it to the **entire epoch's** rewards:

```cairo
let commission = staker_pool_info.commission();
``` [3](#0-2) 

The commission commitment mechanism (`set_commission_commitment`) allows a staker to set a `max_commission` ceiling and then freely move commission to any value ≤ `max_commission` (including **upward** moves) while the commitment is active:

```cairo
if self.is_commission_commitment_active(:commission_commitment) {
    assert!(commission <= commission_commitment.max_commission, ...);
    assert!(commission != old_commission, ...);
}
``` [4](#0-3) 

There is **no** constraint requiring `commission < old_commission` when a commitment is active — only that it differs from the current value and stays within `max_commission`. This is the only path that allows a commission **increase**.

`set_commission_commitment` itself requires only that `max_commission >= current_commission`:

```cairo
let current_commission = staker_pool_info.commission();
assert!(current_commission <= max_commission, "{}", Error::MAX_COMMISSION_TOO_LOW);
``` [5](#0-4) 

---

### Impact Explanation

A staker can steal the entire epoch's pool rewards from delegators. Delegators who delegated expecting a low commission (e.g., 0%) receive zero rewards for the epoch because the commission is retroactively applied at 100% at attestation time. This is **theft of unclaimed yield** — the delegators earned rewards throughout the epoch at the advertised commission rate, but the staker captures all of it by changing commission just before attesting.

---

### Likelihood Explanation

The attack requires the staker to:
1. Have an active `CommissionCommitment` with a high `max_commission`.
2. Call `set_commission` to raise commission before attesting.
3. Call `attest` (via the attestation contract).

All three steps are callable by the staker themselves — no privileged role, no external dependency. The staker controls the timing of their own attestation within the attestation window. The setup (steps 1–2) can be prepared in advance, and the exploit (steps 3–4) executes atomically within a single epoch. Any staker with a pool and an active commitment can execute this.

---

### Recommendation

Before writing the new commission value, settle the current epoch's rewards using the old commission rate. Alternatively, make commission changes only take effect from the **next epoch** by storing a `pending_commission` that is applied at the epoch boundary, similar to how balance changes are deferred via the `StakerBalanceTrace`.

---

### Proof of Concept

1. Staker stakes and opens a STRK pool with `commission = 0`.
2. Staker calls `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)`.
3. Delegators enter the pool, expecting 0% commission.
4. The epoch progresses; rewards accrue.
5. The attestation window opens. Staker calls `set_commission(commission: 10000)` — allowed because `10000 <= max_commission` and `10000 != 0`.
6. Staker immediately calls `attest` via the attestation contract.
7. `calculate_staker_pools_rewards` reads `commission = 10000`, computes `commission_rewards = pool_rewards_including_commission`, and `pool_rewards = 0`.
8. Delegators receive **zero** rewards for the entire epoch. The staker receives all pool rewards as commission. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L725-743)
```text
        fn set_commission(ref self: ContractState, commission: Commission) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(commission <= COMMISSION_DENOMINATOR, "{}", Error::COMMISSION_OUT_OF_RANGE);
            let staker_address = get_caller_address();
            let staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);

            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            if let Option::Some(old_commission) = staker_pool_info.commission.read() {
                self
                    .update_commission(
                        :staker_address, :staker_pool_info, :old_commission, :commission,
                    );
            } else {
                staker_pool_info.commission.write(Option::Some(commission));
                self.emit(Events::CommissionInitialized { staker_address, commission });
            }
        }
```

**File:** src/staking/staking.cairo (L769-770)
```text
            let current_commission = staker_pool_info.commission();
            assert!(current_commission <= max_commission, "{}", Error::MAX_COMMISSION_TOO_LOW);
```

**File:** src/staking/staking.cairo (L1583-1589)
```text
                if self.is_commission_commitment_active(:commission_commitment) {
                    assert!(
                        commission <= commission_commitment.max_commission,
                        "{}",
                        Error::INVALID_COMMISSION_WITH_COMMITMENT,
                    );
                    assert!(commission != old_commission, "{}", Error::INVALID_SAME_COMMISSION);
```

**File:** src/staking/staking.cairo (L1599-1600)
```text
            // Update commission in storage.
            staker_pool_info.commission.write(Option::Some(commission));
```

**File:** src/staking/staking.cairo (L1964-1964)
```text
            let commission = staker_pool_info.commission();
```

**File:** src/staking/staking.cairo (L1989-1991)
```text
                let (commission_rewards, pool_rewards) = split_rewards_with_commission(
                    rewards_including_commission: pool_rewards_including_commission, :commission,
                );
```
