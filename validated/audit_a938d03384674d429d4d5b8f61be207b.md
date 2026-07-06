### Title
Unbounded `stakers` Vec growth enables griefing of `get_stakers` via repeated stake/unstake cycles — (File: src/staking/staking.cairo)

---

### Summary
The `stakers` storage Vec in the Staking contract is append-only: entries are added on every `stake()` call but **never removed** when a staker unstakes. The `get_stakers` consensus function iterates over the entire Vec unconditionally. An unprivileged attacker can inflate this Vec by cycling through many addresses (each staking the minimum amount and then unstaking), causing `get_stakers` to consume unbounded gas and eventually become uncallable.

---

### Finding Description

When a new staker registers, their address is pushed onto the `stakers` Vec: [1](#0-0) 

The storage comment explicitly acknowledges the design: [2](#0-1) 

`get_stakers`, the consensus-critical view function, iterates over **every entry ever pushed**, including all long-since-unstaked addresses: [3](#0-2) 

The `is_staker_active` check only skips inactive entries; it does not prevent the iteration cost from growing. Each inactive entry still costs a storage read and a branch.

`remove_staker` writes a zero balance into the trace but does **not** clear the `stakers` Vec entry: [4](#0-3) 

Because `initialize_staker_own_balance_trace` asserts the trace is empty before allowing a re-stake, the same address cannot be reused: [5](#0-4) 

This means each stake/unstake cycle permanently consumes one Vec slot and requires a fresh address, but the attacker is not prevented from doing so at scale.

---

### Impact Explanation

`get_stakers` is the function consensus nodes call to build the validator set for a given epoch. As the Vec grows, each call to `get_stakers` performs more storage reads. In Starknet, even view/`@ContractState` functions are subject to execution resource limits when called by nodes or sequencers. A sufficiently large Vec causes `get_stakers` to exceed those limits and revert, making the validator set permanently unretrievable. This maps to **Medium — Unbounded gas consumption / griefing with damage to the protocol**.

---

### Likelihood Explanation

Any unprivileged address holding the minimum stake can participate. The exit wait window (~1 week) and minimum stake requirement slow the attack but do not prevent it. A well-funded attacker can run many addresses in parallel, compressing the timeline. The cost is linear in the number of slots inflated; there is no protocol-level cap on the Vec size.

---

### Recommendation

1. **Remove stakers from the Vec on `unstake_action`**: Replace the `Vec` with an `IterableMap` (already used for `btc_tokens`) so entries can be deleted.
2. **Alternatively**, maintain a separate `active_staker_count` and a compact active-only index, and iterate only over that index in `get_stakers`.
3. **Short-term mitigation**: Add a hard cap on `stakers.len()` or charge a non-refundable registration fee to raise the cost of the attack.

---

### Proof of Concept

```
1. Attacker controls N addresses, each pre-funded with min_stake STRK.
2. For each address A_i:
   a. A_i calls stake(reward_address, operational_address, min_stake)
      → stakers.push(A_i)  [Vec length += 1]
   b. A_i calls unstake_intent()
   c. After exit_wait_window, A_i calls unstake_action()
      → staker_info[A_i] = None, but stakers Vec still contains A_i
3. Repeat with fresh addresses.
4. After enough cycles, get_stakers(epoch_id) iterates over all N dead entries
   plus the live ones, consuming O(N) storage reads.
5. Once N is large enough, get_stakers reverts with out-of-resources,
   and consensus nodes can no longer retrieve the validator set.
```

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

**File:** src/staking/staking.cairo (L2020-2023)
```text
            assert!(
                self.staker_own_balance_trace.entry(key: staker_address).is_empty(),
                "{}",
                Error::STAKER_ADDRESS_ALREADY_USED,
```
