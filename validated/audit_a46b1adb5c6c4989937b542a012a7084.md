### Title
Unbounded Growth of `stakers` Vec Causes Unbounded Gas Consumption in `get_stakers` - (File: `src/staking/staking.cairo`)

### Summary
The `stakers` storage Vec in `staking.cairo` is append-only: staker addresses are pushed on `stake()` but never removed on `unstake_action()`. The `get_stakers` consensus function iterates over the entire Vec on every call. As stakers cycle through the protocol, the Vec grows without bound, making `get_stakers` progressively more expensive until it exceeds the block gas limit.

### Finding Description

The `stakers` field is declared with an explicit developer note acknowledging the issue:

```
/// Vector of staker addresses.
/// **Note**: Stakers are not removed from this vector when they unstake.
stakers: Vec<ContractAddress>,
``` [1](#0-0) 

On every `stake()` call, the caller's address is appended:

```cairo
// Add staker address to the stakers vector.
self.stakers.push(staker_address);
``` [2](#0-1) 

On `unstake_action()`, `remove_staker()` is called, which zeroes out `staker_info`, clears the operational address mapping, and emits `DeleteStaker` — but never touches the `stakers` Vec: [3](#0-2) 

The consensus-critical `get_stakers` function iterates over **every element** of `self.stakers` using `into_iter_full_range()`, performing a storage read and an `is_staker_active` check per entry:

```cairo
for staker_address_ptr in self.stakers.into_iter_full_range() {
    let staker_address = staker_address_ptr.read();
    if !self.is_staker_active(:staker_address, :epoch_id) {
        continue;
    }
    ...
}
``` [4](#0-3) 

Each exited staker permanently adds one dead iteration to every future `get_stakers` call.

### Impact Explanation

`get_stakers` is the consensus entrypoint used to determine the active validator set for a given epoch. As the `stakers` Vec accumulates stale entries from all historical stakers who have since exited, the gas cost of `get_stakers` grows linearly and without bound. Once the Vec is large enough, `get_stakers` will exceed the Starknet block gas limit and become permanently uncallable, breaking the consensus layer's ability to read the validator set.

**Impact: Medium — Unbounded gas consumption** (matches allowed scope).

### Likelihood Explanation

The Starknet staking protocol is designed for long-term operation with a large and rotating validator set. Stakers naturally join and leave over time. No special attacker is needed — normal protocol usage over months/years will grow the Vec. A motivated attacker can accelerate this by repeatedly staking with different addresses (each meeting `min_stake`) and then unstaking, since `assert_staker_address_not_reused` prevents re-use of the same address but not fresh addresses. [5](#0-4) 

### Recommendation

Remove the staker's address from the `stakers` Vec during `remove_staker` (or `unstake_action`). Because Starknet's `Vec` does not support O(1) removal, the standard approach is a swap-and-pop: store each staker's index in the Vec in a companion `Map<ContractAddress, u64>`, swap the departing staker with the last element, update the swapped element's index, then pop the last element. Alternatively, replace the `Vec` with an `IterableMap` (already used for `btc_tokens`) which supports deletion natively. [6](#0-5) 

### Proof of Concept

1. Deploy the staking contract.
2. Have `N` distinct addresses each call `stake()` with the minimum stake, then `unstake_intent()`, wait for the exit window, then `unstake_action()`.
3. After all `N` stakers have exited, call `get_stakers(current_epoch)`.
4. Observe that `get_stakers` iterates over all `N` stale entries in `self.stakers`, performing `N` storage reads and `is_staker_active` checks, even though the result is an empty array.
5. As `N` grows, the gas cost of `get_stakers` grows linearly. At a sufficiently large `N`, the call exceeds the block gas limit and reverts, permanently breaking consensus validator-set reads.

### Citations

**File:** src/staking/staking.cairo (L64-67)
```text
    use starkware_utils::storage::iterable_map::{
        IterableMap, IterableMapIntoIterImpl, IterableMapReadAccessImpl, IterableMapTrait,
        IterableMapWriteAccessImpl, MutableIterableMapTrait,
    };
```

**File:** src/staking/staking.cairo (L167-169)
```text
        /// Vector of staker addresses.
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
```

**File:** src/staking/staking.cairo (L303-303)
```text
            self.assert_staker_address_not_reused(:staker_address);
```

**File:** src/staking/staking.cairo (L347-348)
```text
            // Add staker address to the stakers vector.
            self.stakers.push(staker_address);
```

**File:** src/staking/staking.cairo (L918-935)
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
