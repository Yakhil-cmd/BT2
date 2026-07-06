### Title
Unbounded `stakers` Vec Growth Causes Permanent DoS of `get_stakers()` via Unbounded Gas Consumption - (File: `src/staking/staking.cairo`)

---

### Summary

The `stakers` storage `Vec` in `staking.cairo` is appended to on every `stake()` call but is **never pruned** when a staker exits via `unstake_action()`. The consensus-critical `get_stakers()` function iterates over the **entire** Vec on every call, including all historical staker addresses that have long since unstaked. As the protocol ages and staker churn accumulates, this iteration grows without bound, eventually exceeding the block gas limit and permanently breaking the validator-set query.

---

### Finding Description

On every `stake()` call, the staker's address is appended to the `stakers` Vec: [1](#0-0) 

The storage declaration itself carries an explicit acknowledgment of the problem: [2](#0-1) 

When a staker fully exits via `unstake_action()` → `remove_staker()`, the staker's `staker_info` is cleared and the operational address mapping is zeroed, but **no entry is removed from `stakers`**: [3](#0-2) 

`get_stakers()` then iterates over the **full range** of this ever-growing Vec: [4](#0-3) 

For each entry — including every address that has already unstaked — the loop performs multiple storage reads: `is_staker_active`, `get_staker_staking_power_at_epoch`, `get_public_key_at_epoch`, `get_peer_id_at_epoch`. Inactive stakers are skipped via `continue`, but the storage reads still occur and consume gas.

---

### Impact Explanation

`get_stakers()` is the consensus-layer function that returns the validator set for a given epoch. As the number of historical (already-exited) stakers accumulates over the protocol's lifetime, each call to `get_stakers()` must perform an ever-increasing number of storage reads. Once the Vec is large enough, the function will exceed the Starknet block gas limit on every invocation, making it permanently unusable.

This constitutes **unbounded gas consumption** leading to a permanent DoS of the validator-set query, which is a Medium-severity impact under the allowed scope.

---

### Likelihood Explanation

The likelihood is **high over time** and requires no privileged access. Any unprivileged address can call `stake()` followed by `unstake_intent()` + `unstake_action()` to permanently add a dead entry to the `stakers` Vec. A griefing attacker can repeat this cycle (subject only to the `min_stake` requirement and the exit wait window) to accelerate the growth of the Vec. Even without deliberate griefing, normal protocol operation will cause the Vec to grow monotonically as validators rotate over months and years.

---

### Recommendation

Remove the staker's address from the `stakers` Vec during `remove_staker()` (e.g., swap-and-pop pattern), or maintain a separate counter of active stakers and use a compacting data structure. Alternatively, replace the Vec with an `IterableMap` (already used for `btc_tokens`) that supports deletion, so that `get_stakers()` only iterates over currently-registered stakers.

---

### Proof of Concept

```
1. Attacker calls stake() N times from N different addresses (each with min_stake).
   → stakers Vec grows by N entries.

2. Each attacker address calls unstake_intent(), waits exit_wait_window, calls unstake_action().
   → staker_info is cleared for each address.
   → stakers Vec still has N dead entries (never pruned).

3. Any caller invokes get_stakers(epoch_id).
   → The loop at line 918 iterates over all N + (live stakers) entries.
   → For each dead entry: is_staker_active() reads staker_info (None) → returns false → continue.
   → Gas cost scales linearly with total historical staker count.

4. After enough churn, get_stakers() exceeds the block gas limit on every call,
   permanently breaking the consensus validator-set query.
``` [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L167-169)
```text
        /// Vector of staker addresses.
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
```

**File:** src/staking/staking.cairo (L347-348)
```text
            // Add staker address to the stakers vector.
            self.stakers.push(staker_address);
```

**File:** src/staking/staking.cairo (L901-937)
```text
        fn get_stakers(
            self: @ContractState, epoch_id: Epoch,
        ) -> Span<(ContractAddress, StakingPower, Option<PublicKey>, Option<PeerId>)> {
            let curr_epoch = self.get_current_epoch();
            assert!(
                curr_epoch <= epoch_id && epoch_id < curr_epoch + K.into(),
                "{}",
                Error::INVALID_EPOCH,
            );

            let (strk_total_stake, btc_total_stake) = self
                .get_total_staking_power_at_epoch(:epoch_id);

            let mut stakers: Array<
                (ContractAddress, StakingPower, Option<PublicKey>, Option<PeerId>),
            > =
                array![];
            for staker_address_ptr in self.stakers.into_iter_full_range() {
                let staker_address = staker_address_ptr.read();
                if !self.is_staker_active(:staker_address, :epoch_id) {
                    continue;
                }

                let staking_power = self
                    .get_staker_staking_power_at_epoch(
                        :staker_address, :epoch_id, :strk_total_stake, :btc_total_stake,
                    );
                if staking_power.is_zero() {
                    continue;
                }

                let public_key = self.get_public_key_at_epoch(:staker_address, :epoch_id);
                let peer_id = self.get_peer_id_at_epoch(:staker_address, :epoch_id);
                stakers.append((staker_address, staking_power, public_key, peer_id));
            }
            stakers.span()
        }
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
