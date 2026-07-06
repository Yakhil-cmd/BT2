### Title
Unbounded Gas Consumption in `get_stakers` Due to Unbounded `stakers` Vec Growth - (File: `src/staking/staking.cairo`)

### Summary
The `stakers` storage vector in the `Staking` contract grows without bound because stakers are appended on every `stake()` call but **never removed** when they unstake. The `get_stakers` function iterates over the entire vector on every call, making its gas cost proportional to the total number of stakers that have ever existed. An attacker can register many staker addresses (each meeting only the minimum stake requirement) to inflate this vector, causing `get_stakers` to exceed the Starknet block gas limit and become permanently uncallable.

### Finding Description

In `src/staking/staking.cairo`, the `stake()` function unconditionally appends the new staker address to the `stakers` Vec:

```cairo
// Add staker address to the stakers vector.
self.stakers.push(staker_address);
```

The storage comment explicitly acknowledges this:

```cairo
/// Vector of staker addresses.
/// **Note**: Stakers are not removed from this vector when they unstake.
stakers: Vec<ContractAddress>,
```

The `get_stakers()` function (part of `IStakingConsensus`) iterates over the **full range** of this vector on every invocation:

```cairo
for staker_address_ptr in self.stakers.into_iter_full_range() {
    let staker_address = staker_address_ptr.read();
    if !self.is_staker_active(:staker_address, :epoch_id) {
        continue;
    }
    // ... per-staker storage reads for staking_power, public_key, peer_id
    stakers.append((staker_address, staking_power, public_key, peer_id));
}
```

Each iteration performs multiple storage reads (`is_staker_active`, `get_staker_staking_power_at_epoch`, `get_public_key_at_epoch`, `get_peer_id_at_epoch`). There is no cap on the size of `stakers`, and there is no mechanism to prune exited stakers from the vector.

### Impact Explanation

`get_stakers` is a critical consensus function — it is the on-chain source of truth for the validator set used by the consensus layer. If this function becomes uncallable due to gas exhaustion, the protocol cannot serve the validator committee for any epoch, permanently freezing the consensus reward distribution mechanism and blocking any caller that depends on this view. This maps to **Unbounded gas consumption** (Medium) and potentially **Permanent freezing of unclaimed yield** (High) if the consensus reward pipeline depends on this function being callable.

### Likelihood Explanation

Any address holding the minimum stake amount can register as a staker. After calling `unstake_intent` and `unstake_action`, the staker recovers their funds but their address remains in the vector forever. An attacker can cycle through many addresses — each staking the minimum, then unstaking — to inflate the vector at a cost proportional to `min_stake` per entry. Since `min_stake` is a protocol parameter that can be set low, and the attacker recovers their principal after each cycle, the net cost per poisoned slot is only the gas cost of `stake` + `unstake_intent` + `unstake_action`. With enough addresses, `get_stakers` will exceed the block gas limit.

### Recommendation

1. **Cap the stakers vector**: Enforce a maximum number of registered stakers (e.g., 10,000) and reject `stake()` calls that would exceed it.
2. **Compact on removal**: When `unstake_action` is called, swap the staker's slot with the last element and pop the vector, keeping the vector size equal to the number of currently active stakers.
3. **Lazy/paginated iteration**: Redesign `get_stakers` to support pagination (offset + limit) so no single call iterates the full vector.

### Proof of Concept

1. Attacker controls N addresses `A_1 ... A_N`, each funded with `min_stake` STRK.
2. For each `A_i`: call `stake(reward_address, operational_address_i, min_stake)` → `A_i` is appended to `self.stakers`.
3. For each `A_i`: call `unstake_intent()` then (after `exit_wait_window`) `unstake_action()` → funds returned, but `A_i` remains in `self.stakers` forever.
4. After N such cycles, `self.stakers` has length N with all entries being inactive stakers.
5. Any call to `get_stakers(epoch_id)` now iterates N entries, each requiring multiple storage reads. At sufficient N, the transaction exceeds the Starknet block gas limit and reverts.
6. `get_stakers` is permanently broken for any `epoch_id`. [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/staking/staking.cairo (L167-169)
```text
        /// Vector of staker addresses.
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
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
