### Title
Unbounded `stakers` Vec Causes Unbounded Gas Consumption in `get_stakers()` - (File: src/staking/staking.cairo)

### Summary
The `stakers` storage Vec in the `Staking` contract grows monotonically — stakers are appended on `stake()` but **never removed** even after `unstake_action()` completes. The `get_stakers()` function iterates over the entire Vec unconditionally. Any unprivileged user can repeatedly stake with the minimum amount, wait out the exit window, unstake (recovering their principal), and repeat — permanently inflating the Vec at near-zero net cost. Over time this makes `get_stakers()` prohibitively expensive, eventually causing it to exceed Starknet execution limits and fail.

### Finding Description

In `src/staking/staking.cairo`, every call to `stake()` appends the caller's address to the `stakers` Vec:

```cairo
// line 348
self.stakers.push(staker_address);
```

The storage declaration itself carries an explicit warning that removal never happens:

```cairo
/// Vector of staker addresses.
/// **Note**: Stakers are not removed from this vector when they unstake.
stakers: Vec<ContractAddress>,   // line 168-169
```

`remove_staker()` (the internal cleanup called by `unstake_action`) clears `staker_info`, the operational-address mapping, and pool data, but never touches `stakers`:

```cairo
fn remove_staker(...) {
    self.insert_staker_own_balance(:staker_address, own_balance: Zero::zero());
    self.staker_info.write(staker_address, VInternalStakerInfo::None);
    self.operational_address_to_staker_address.write(operational_address, Zero::zero());
    // stakers Vec is never modified here
    ...
}
```

`get_stakers()` iterates over the **full** Vec on every call:

```cairo
for staker_address_ptr in self.stakers.into_iter_full_range() {
    let staker_address = staker_address_ptr.read();
    if !self.is_staker_active(:staker_address, :epoch_id) {
        continue;
    }
    ...
}
```

Each iteration performs at least one storage read (`is_staker_active`), and for active stakers several more (`get_staker_staking_power_at_epoch`, `get_public_key_at_epoch`, `get_peer_id_at_epoch`). Stale (unstaked) entries still cost one storage read each to skip.

### Impact Explanation

`get_stakers()` is the canonical on-chain source of the validator committee for a given epoch. Consensus infrastructure and any on-chain consumer that calls it will face linearly growing execution cost proportional to the total number of addresses ever staked. Once the Vec is large enough, the function will exceed Starknet's per-transaction execution limit and revert on every call, permanently breaking the ability to query the validator set. This constitutes **unbounded gas consumption** and griefing of the protocol with no profit motive required.

### Likelihood Explanation

The attack is cheap: the attacker's principal is fully returned after `unstake_action()`. The only recurring cost is gas for `stake()`, `unstake_intent()`, and `unstake_action()`. On Starknet, where gas fees are low, an attacker can cycle through thousands of addresses over time. The minimum stake (`min_stake`) is a governance parameter and does not prevent the attack — it only controls the capital temporarily locked per cycle, not the permanent Vec growth.

### Recommendation

Remove the staker's address from the `stakers` Vec inside `remove_staker()` (or equivalently inside `unstake_action()`). Because Cairo's `Vec` does not support O(1) removal, a common pattern is to swap the target element with the last element and then pop, or to maintain a separate `IterableMap` keyed by staker address (similar to how `btc_tokens` uses `IterableMap`) that supports deletion. Alternatively, track a separate "active staker count" and skip stale entries with a tombstone flag, but this does not reduce iteration cost. The cleanest fix is to use a data structure that supports deletion.

### Proof of Concept

1. Attacker controls addresses `A_1 … A_N`, each funded with `min_stake` STRK.
2. For each `A_i`: call `stake(...)` → `stakers` Vec grows by 1.
3. After `exit_wait_window` seconds: call `unstake_intent()` then `unstake_action()` → principal returned, but `A_i` remains in `stakers` forever.
4. Repeat with fresh addresses. Each cycle costs only gas; principal is recovered.
5. After enough cycles, `get_stakers(epoch_id)` iterates over `N` entries, each requiring at least one storage read. At sufficient `N`, the call exceeds the Starknet execution limit and reverts, making the validator-set query permanently unavailable. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L167-170)
```text
        /// Vector of staker addresses.
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
        /// Map token address to its decimals.
```

**File:** src/staking/staking.cairo (L346-349)
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
