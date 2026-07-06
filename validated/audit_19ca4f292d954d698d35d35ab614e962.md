### Title
Stakers Never Removed from `stakers` Vec Enables Unbounded Gas Consumption in `get_stakers()` - (File: src/staking/staking.cairo)

### Summary

The `stakers` storage `Vec` in the Staking contract grows without bound because staker addresses are appended on `stake()` but never removed on `unstake_action()`. The `get_stakers()` function iterates over the **full range** of this vector on every call. An adversary can inflate the vector with dead entries by repeatedly staking with fresh addresses and then unstaking, making `get_stakers()` progressively more expensive until it becomes unusable.

### Finding Description

Every call to `stake()` appends the caller's address to `self.stakers`: [1](#0-0) 

The storage declaration itself carries an explicit developer note acknowledging the omission: [2](#0-1) 

`remove_staker()`, called during `unstake_action()`, clears `staker_info`, zeroes balances, and removes the operational-address mapping — but never touches the `stakers` Vec: [3](#0-2) 

`get_stakers()` iterates over the **entire** vector on every invocation: [4](#0-3) 

Dead entries are skipped via `is_staker_active`, but the loop body still executes a storage read and the activity check for every dead slot, consuming gas proportional to the total number of ever-registered stakers.

Address reuse is blocked by `assert_staker_address_not_reused`, which checks that `staker_own_balance_trace` is empty: [5](#0-4) 

Because `remove_staker` inserts a zero-balance checkpoint into `staker_own_balance_trace`, the trace is non-empty after exit, permanently preventing address reuse. Each attack iteration therefore requires a fresh address — but the staked STRK is fully returned after `unstake_action`, so the only recurring cost to the adversary is gas.

### Impact Explanation

`get_stakers()` is the function the consensus layer calls to build the validator set for a given epoch. As the `stakers` Vec grows, the gas cost of `get_stakers()` grows linearly with the total number of ever-registered stakers. An adversary who inflates the vector sufficiently can cause `get_stakers()` to exceed the Starknet gas limit, making it impossible for the consensus layer to retrieve the active validator set. This constitutes **unbounded gas consumption** and **griefing with damage to the protocol** — both listed Medium impacts.

### Likelihood Explanation

The attack requires only gas (STRK principal is returned after each unstake cycle). An adversary needs a supply of fresh addresses and enough STRK to cover the `min_stake` requirement per cycle, but since the principal is recovered, the net cost per iteration is only transaction fees. The attack is therefore economically feasible for a motivated adversary over time, especially if `min_stake` is low relative to the cost of disrupting consensus.

### Recommendation

Remove the staker address from the `stakers` Vec when `remove_staker` is called, or replace the `Vec` with a data structure that supports O(1) deletion (e.g., a swap-and-pop pattern or an `IterableMap`). Alternatively, maintain a separate counter of active stakers and enforce a cap, or redesign `get_stakers()` to avoid iterating over the full historical set (e.g., by maintaining a separate active-staker set that is updated on entry and exit).

### Proof of Concept

1. Adversary controls addresses `A1, A2, …, AN`, each funded with `min_stake` STRK.
2. For each `Ai`:
   - Call `stake(reward_address, operational_address_i, min_stake)` → `Ai` is appended to `self.stakers`.
   - Call `unstake_intent()` → sets exit timestamp.
   - After `exit_wait_window`, call `unstake_action(Ai)` → STRK returned; `Ai` remains in `self.stakers` as a dead entry.
3. After N cycles, `self.stakers` contains N dead entries.
4. Any call to `get_stakers(epoch_id)` now iterates over all N entries:
   - Each iteration reads `staker_address_ptr` from storage and calls `is_staker_active`.
   - For dead entries, `is_staker_active` returns `false` and the loop `continue`s — but the storage reads still consume gas.
5. For sufficiently large N, `get_stakers()` exceeds the block/call gas limit, permanently breaking consensus validator-set retrieval.

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

**File:** src/staking/staking.cairo (L918-936)
```text
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

**File:** src/staking/staking.cairo (L2204-2217)
```text
        fn assert_staker_address_not_reused(self: @ContractState, staker_address: ContractAddress) {
            // Catch stakers that entered in an older version (V0 or V1), and performed
            // `exit_action` in V1.
            assert!(
                self.staker_balance_trace.entry(key: staker_address).is_empty(),
                "{}",
                Error::STAKER_ADDRESS_ALREADY_USED_IN_V1,
            );
            assert!(
                self.staker_own_balance_trace.entry(key: staker_address).is_empty(),
                "{}",
                Error::STAKER_ADDRESS_ALREADY_USED,
            );
        }
```
