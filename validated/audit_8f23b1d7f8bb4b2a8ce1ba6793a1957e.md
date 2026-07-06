### Title
Unbounded `stakers` Vector Causes Unbounded Gas Consumption in `get_stakers` — (File: `src/staking/staking.cairo`)

---

### Summary

The `stakers` storage vector in the `Staking` contract grows monotonically as stakers register, but stakers are **never removed** from it when they unstake. The `get_stakers` function iterates over the full range of this vector on every call. An unprivileged attacker can inflate the vector indefinitely by repeatedly staking and unstaking with fresh addresses, causing `get_stakers` to consume unbounded resources and eventually become uncallable.

---

### Finding Description

**Root cause — append-only `stakers` vector:**

Every call to `stake()` appends the caller's address to the `stakers` vector:

```cairo
// Add staker address to the stakers vector.
self.stakers.push(staker_address);
```

The storage comment is explicit:

```
/// Vector of staker addresses.
/// **Note**: Stakers are not removed from this vector when they unstake.
stakers: Vec<ContractAddress>,
```

`remove_staker()` (called from `unstake_action()`) clears `staker_info`, zeroes the own-balance trace, and removes the operational-address mapping — but it **never touches `stakers`**.

**Unbounded iteration in `get_stakers`:**

`get_stakers` iterates over the **full** vector on every invocation:

```cairo
for staker_address_ptr in self.stakers.into_iter_full_range() {
    let staker_address = staker_address_ptr.read();
    if !self.is_staker_active(:staker_address, :epoch_id) {
        continue;   // inactive entries are skipped but still read from storage
    }
    // ... per-staker storage reads for balance, public key, peer id
}
```

Every element — active or long-since-unstaked — requires at least one storage read (`staker_address_ptr.read()`) plus the `is_staker_active` check. The loop has no upper bound tied to the number of *currently active* stakers.

**Attacker-controlled growth:**

`assert_staker_address_not_reused` blocks address reuse after `unstake_action`, but the attacker simply uses a fresh address each time. The minimum stake is fully returned after `unstake_action`, so the only cost is gas for the stake/unstake round-trip. Each cycle permanently adds one dead entry to `stakers`.

---

### Impact Explanation

`get_stakers` is the entry point used by the Starknet consensus layer to obtain the validator set for a given epoch (`IStakingConsensus::get_stakers`). As the dead-entry count grows, every call to this function performs proportionally more storage reads. Once the vector is large enough, the function will exceed Starknet's per-transaction or per-call resource limits, making it permanently uncallable. This prevents the consensus layer from retrieving the validator set, disrupting protocol operation.

**Impact class:** Medium — unbounded gas consumption / griefing with damage to the protocol.

---

### Likelihood Explanation

The attack requires no privileged access. Any address holding the minimum stake amount can participate. Because the stake is returned in full after `unstake_action`, the attacker's net cost per iteration is only gas. The attack is therefore economically viable at scale and can be executed by any public caller.

---

### Recommendation

1. **Pagination:** Add `offset` / `limit` parameters to `get_stakers` so callers can page through the vector in bounded chunks.
2. **Active-staker index:** Maintain a separate counter of currently active stakers and use it to bound the loop, or maintain a separate compact vector of active addresses that is updated on `unstake_action`.
3. **Swap-and-pop on removal:** When a staker calls `unstake_action`, swap their entry with the last element in `stakers` and pop the tail, keeping the vector compact. (Requires tracking each staker's index.)

---

### Proof of Concept

```
1. Attacker funds N fresh addresses, each with `min_stake` STRK.
2. For each address i in [1..N]:
     a. Call stake() → address i appended to stakers[i-1].
     b. Call unstake_intent() → staker removed from total_stake; stakers vector unchanged.
     c. Advance time past exit_wait_window.
     d. Call unstake_action() → staker_info deleted; stakers[i-1] still holds address i.
3. stakers.len() == N; all entries are inactive.
4. Any call to get_stakers(epoch_id) now iterates N entries, each requiring:
     - staker_address_ptr.read()          (1 storage read)
     - is_staker_active(...)              (trace reads)
   Total storage reads ≈ O(N).
5. As N → block/call resource limit, get_stakers reverts, permanently
   blocking the consensus layer from reading the validator set.
```

**Key code references:**

- `stakers` vector declaration and note: [1](#0-0) 
- `stake()` appending to the vector: [2](#0-1) 
- `get_stakers` full-range iteration: [3](#0-2) 
- `remove_staker` — no removal from `stakers`: [4](#0-3) 
- `assert_staker_address_not_reused` (blocks reuse, not new addresses): [5](#0-4)

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
