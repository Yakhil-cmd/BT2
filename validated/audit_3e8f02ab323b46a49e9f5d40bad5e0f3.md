### Title
Unbounded `stakers` Vec Growth via Stake-Unstake Cycling Causes DoS in `get_stakers()` - (File: `src/staking/staking.cairo`)

### Summary
The `stakers` storage Vec in the Staking contract grows permanently with every new staker address and is never pruned, even after a staker fully exits via `unstake_action()`. The `get_stakers()` function iterates over the **entire** Vec on every call. An unprivileged attacker can inflate this Vec at the cost of gas alone (stake principal is fully returned), eventually making `get_stakers()` revert out-of-gas and disrupting the consensus layer's ability to read active staker sets.

### Finding Description

**Root cause — Vec grows, never shrinks.**

`src/staking/staking.cairo` line 169 declares:

```cairo
/// Vector of staker addresses.
/// **Note**: Stakers are not removed from this vector when they unstake.
stakers: Vec<ContractAddress>,
``` [1](#0-0) 

Every call to `stake()` appends the caller's address unconditionally:

```cairo
// Add staker address to the stakers vector.
self.stakers.push(staker_address);
``` [2](#0-1) 

`unstake_action()` calls `remove_staker()` and clears pool data, but **never touches `self.stakers`**:

```cairo
self.remove_staker(:staker_address, :staker_info, :staker_pool_info);
// ...
staker_pool_info.pools.clear();
``` [3](#0-2) 

`remove_staker()` itself only zeroes `staker_info`, the operational-address mapping, and commission fields — the Vec entry is untouched: [4](#0-3) 

**Unbounded iteration in `get_stakers()`.**

`IStakingConsensus::get_stakers()` iterates over `self.stakers.into_iter_full_range()` — the **full** Vec including all ghost (unstaked) entries:

```cairo
for staker_address_ptr in self.stakers.into_iter_full_range() {
    let staker_address = staker_address_ptr.read();
    if !self.is_staker_active(:staker_address, :epoch_id) {
        continue;
    }
    // ...
}
``` [5](#0-4) 

Each ghost entry still costs a storage read + `is_staker_active` check per iteration. There is no cap on Vec length.

**Address-reuse guard does not prevent inflation.**

`assert_staker_address_not_reused()` prevents the *same* address from staking twice, but does nothing to prevent an attacker from using a fresh address each time: [6](#0-5) 

**Confirmed by existing test.**

The flow test explicitly verifies that a staker who has already completed `unstake_action()` (`staker_in_action`) remains in the Vec at index 3:

```cairo
let actual_stakers = system.staking.get_stakers();
assert!(actual_stakers.len() == 4);
assert!(actual_stakers.at(index: 3) == @staker_in_action.staker.address);
``` [7](#0-6) 

### Impact Explanation

`get_stakers()` is the primary interface used by the consensus layer to enumerate active validators and their staking weights for a given epoch. As the `stakers` Vec grows, every call to `get_stakers()` must iterate over an ever-larger set of dead entries. Once the Vec is large enough, the function will exceed the block gas limit and revert, making it impossible for any caller to read the active staker set. This matches the **Unbounded gas consumption / griefing** impact class.

### Likelihood Explanation

The attack is cheap: the attacker's only cost is gas per stake/unstake cycle, because `unstake_action()` returns the full principal. On Starknet, transaction fees are low. An attacker can automate the cycle across thousands of fresh addresses. No privileged access, no oracle manipulation, and no external dependency is required — only the public `stake()` and `unstake_action()` entry points.

### Recommendation

1. **Lazy deletion**: When `unstake_action()` is called, overwrite the staker's slot in the Vec with a sentinel (e.g., `ContractAddress::zero()`) and skip zero entries in `get_stakers()`. This avoids the cost of compacting the Vec.
2. **Swap-and-pop**: Maintain a reverse mapping `staker_address → Vec index` so `unstake_action()` can swap the departing staker with the last element and pop, keeping the Vec compact.
3. **Minimum stake economic deterrent**: Raise `min_stake` to a level that makes mass inflation economically irrational, as a short-term mitigation.

### Proof of Concept

```cairo
// Pseudocode — each iteration adds one permanent ghost entry to `stakers`
for i in 0..N {
    let addr = fresh_address(i);
    // stake min_stake from addr
    staking.stake(reward_address, operational_address, min_stake);  // Vec grows by 1
    // wait exit_wait_window
    staking.unstake_intent();
    advance_time(exit_wait_window);
    staking.unstake_action(addr);  // principal returned; Vec entry NOT removed
}
// After N iterations, get_stakers() must iterate N dead entries on every call.
// At sufficient N, get_stakers() reverts out-of-gas.
assert!(staking.get_stakers(epoch_id).len() == 0);  // would OOG before reaching here
```

The existing test already demonstrates the invariant — `staker_in_action` (fully unstaked) persists at index 3 of the Vec — confirming the ghost-entry accumulation is real and not filtered away. [1](#0-0) [2](#0-1) [8](#0-7)

### Citations

**File:** src/staking/staking.cairo (L167-169)
```text
        /// Vector of staker addresses.
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
```

**File:** src/staking/staking.cairo (L347-349)
```text
            // Add staker address to the stakers vector.
            self.stakers.push(staker_address);

```

**File:** src/staking/staking.cairo (L502-513)
```text
            self.remove_staker(:staker_address, :staker_info, :staker_pool_info);

            // Return stake to staker.
            token_dispatcher
                .checked_transfer(recipient: staker_address, amount: staker_amount.into());
            // Return delegated stake to pools and zero their balances.
            self
                .transfer_to_pools_when_unstake(
                    :staker_address, staker_pool_info: staker_pool_info.as_non_mut(),
                );
            // Clear staker pools.
            staker_pool_info.pools.clear();
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

**File:** src/staking/staking.cairo (L2204-2216)
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
```

**File:** src/flow_test/flows.cairo (L5898-5903)
```text
        let actual_stakers = system.staking.get_stakers();
        assert!(actual_stakers.len() == 4);
        assert!(actual_stakers.at(index: 0) == @staker_with_pool.staker.address);
        assert!(actual_stakers.at(index: 1) == @staker_without_pool.staker.address);
        assert!(actual_stakers.at(index: 2) == @staker_in_intent.staker.address);
        assert!(actual_stakers.at(index: 3) == @staker_in_action.staker.address);
```
