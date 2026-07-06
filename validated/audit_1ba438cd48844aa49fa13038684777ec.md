### Title
Stale `staker_unstake_intent_epoch` Not Cleared in `unstake_action` Permanently Excludes Re-Staked Staker from Consensus — (File: `src/staking/staking.cairo`)

---

### Summary

`unstake_intent` writes `staker_unstake_intent_epoch` for a staker, but `unstake_action` (via `remove_staker`) never clears it. Because `staker_info` *is* cleared on `unstake_action`, the same address can call `stake` again. After re-staking, the stale `staker_unstake_intent_epoch` value persists and causes `get_stakers` to permanently exclude the re-staked staker from consensus, freezing their ability to earn consensus rewards.

---

### Finding Description

**State written — `unstake_intent`:**

`unstake_intent` writes the epoch at which the staker's exit takes effect:

```cairo
self.staker_unstake_intent_epoch.write(staker_address, self.get_epoch_plus_k());
``` [1](#0-0) 

**State NOT cleared — `remove_staker` (called by `unstake_action`):**

`remove_staker` clears `staker_info`, `operational_address_to_staker_address`, `commission`, and `commission_commitment`, but **never touches `staker_unstake_intent_epoch`**:

```cairo
fn remove_staker(...) {
    self.insert_staker_own_balance(:staker_address, own_balance: Zero::zero());
    self.staker_info.write(staker_address, VInternalStakerInfo::None);
    self.operational_address_to_staker_address.write(operational_address, Zero::zero());
    staker_pool_info.commission.write(Option::None);
    staker_pool_info.commission_commitment.write(Option::None);
    // staker_unstake_intent_epoch is never cleared
    ...
}
``` [2](#0-1) 

**Re-entry is possible — `stake`:**

After `unstake_action`, `staker_info` is `VInternalStakerInfo::None`. The `stake` function only checks:

```cairo
assert!(self.staker_info.read(staker_address).is_none(), "{}", Error::STAKER_EXISTS);
``` [3](#0-2) 

So the same address can re-stake immediately after `unstake_action`. No check is made against `staker_unstake_intent_epoch`.

**Stale epoch affects `get_stakers`:**

The test `test_get_stakers_unstake_intent_action` confirms that `get_stakers` uses `staker_unstake_intent_epoch` to exclude stakers: after `unstake_intent`, the staker remains in `get_stakers` for the current epoch but is excluded once `current_epoch >= staker_unstake_intent_epoch`:

```cairo
advance_k_epochs_global();
let stakers = staking_consensus_dispatcher.get_stakers(:epoch_id);
assert!(stakers.len() == 0);  // excluded after K epochs
``` [4](#0-3) 

After re-staking, `staker_info` is valid again, but `staker_unstake_intent_epoch` still holds the old value (set to `epoch + K` at the time of the previous `unstake_intent`). Since the staker has already passed the exit window, `current_epoch >= staker_unstake_intent_epoch`, and `get_stakers` permanently excludes the re-staked staker from consensus.

The `stakers` Vec is never pruned on unstake, confirming the staker's address is still iterated:

```cairo
/// **Note**: Stakers are not removed from this vector when they unstake.
stakers: Vec<ContractAddress>,
``` [5](#0-4) 

---

### Impact Explanation

A staker who unstakes and re-stakes with the same address is permanently excluded from the consensus staker set. They cannot earn consensus-based block rewards for any future epoch. This constitutes **permanent freezing of unclaimed yield** — a High-severity impact under the allowed scope.

---

### Likelihood Explanation

Any staker who legitimately unstakes (e.g., to rotate their operational address, which requires unstaking and re-staking) and re-stakes with the same address triggers this bug. The entry path requires no privilege: `unstake_intent`, `unstake_action`, and `stake` are all callable by the staker themselves. The bug is deterministic and reproducible.

---

### Recommendation

Clear `staker_unstake_intent_epoch` inside `remove_staker` (or directly in `unstake_action`) alongside the other staker state:

```cairo
fn remove_staker(...) {
    self.insert_staker_own_balance(:staker_address, own_balance: Zero::zero());
    self.staker_info.write(staker_address, VInternalStakerInfo::None);
    self.operational_address_to_staker_address.write(operational_address, Zero::zero());
+   self.staker_unstake_intent_epoch.write(staker_address, Zero::zero());
    staker_pool_info.commission.write(Option::None);
    staker_pool_info.commission_commitment.write(Option::None);
    ...
}
```

---

### Proof of Concept

1. Staker calls `stake(...)` at epoch `E`. `staker_unstake_intent_epoch[staker] == 0`.
2. Staker calls `unstake_intent()`. Sets `staker_unstake_intent_epoch[staker] = E + K`.
3. After the exit wait window, staker calls `unstake_action(staker)`. `staker_info[staker]` is cleared to `None`. `staker_unstake_intent_epoch[staker]` **remains `E + K`**.
4. Staker calls `stake(...)` again with the same address. `staker_info[staker]` is now a fresh entry. `staker_unstake_intent_epoch[staker]` is still `E + K`.
5. Current epoch is `>= E + K` (since the exit wait window spans K epochs). `get_stakers` evaluates `current_epoch >= staker_unstake_intent_epoch[staker]` → true → staker is excluded.
6. The re-staked staker earns zero consensus rewards indefinitely. The only escape is to call `unstake_intent` again (overwriting the epoch to a future value), but this forces another full unstake cycle and does not fix the root cause.

### Citations

**File:** src/staking/staking.cairo (L168-169)
```text
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
```

**File:** src/staking/staking.cairo (L297-297)
```text
            assert!(self.staker_info.read(staker_address).is_none(), "{}", Error::STAKER_EXISTS);
```

**File:** src/staking/staking.cairo (L445-446)
```text
            // Write the unstake intent epoch.
            self.staker_unstake_intent_epoch.write(staker_address, self.get_epoch_plus_k());
```

**File:** src/staking/staking.cairo (L1686-1708)
```text
        fn remove_staker(
            ref self: ContractState,
            staker_address: ContractAddress,
            staker_info: InternalStakerInfoLatest,
            staker_pool_info: StoragePath<Mutable<InternalStakerPoolInfoV2>>,
        ) {
            self.insert_staker_own_balance(:staker_address, own_balance: Zero::zero());
            self.staker_info.write(staker_address, VInternalStakerInfo::None);
            let operational_address = staker_info.operational_address;
            self.operational_address_to_staker_address.write(operational_address, Zero::zero());
            staker_pool_info.commission.write(Option::None);
            staker_pool_info.commission_commitment.write(Option::None);
            let pool_contracts = staker_pool_info.get_pools();
            self
                .emit(
                    Events::DeleteStaker {
                        staker_address,
                        reward_address: staker_info.reward_address,
                        operational_address,
                        pool_contracts,
                    },
                );
        }
```

**File:** src/staking/tests/test.cairo (L6010-6013)
```text
    advance_k_epochs_global();
    let epoch_id = staking_dispatcher.get_current_epoch();
    let stakers = staking_consensus_dispatcher.get_stakers(:epoch_id);
    assert!(stakers.len() == 0);
```
