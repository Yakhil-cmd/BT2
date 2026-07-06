### Title
Unbounded `stakers` Vec with Full Linear Iteration in `get_stakers` — (`src/staking/staking.cairo`)

---

### Summary

Every call to `stake()` appends the new staker's address to the `stakers` storage Vec. Stakers are **never removed** from this Vec, even after they fully unstake. The function `get_stakers()` iterates over the **entire** Vec unconditionally via `into_iter_full_range()`. As the protocol matures and the staker count grows, the gas cost of `get_stakers()` grows linearly and without bound, eventually making the function uncallable within block gas limits.

---

### Finding Description

In `src/staking/staking.cairo`, every successful `stake()` call appends the caller's address to `self.stakers`: [1](#0-0) 

There is no corresponding removal. When a staker calls `unstake_intent()` and later `unstake_action()`, their address remains in `self.stakers` permanently.

`get_stakers()` then iterates over every element ever pushed, including all long-since-inactive stakers: [2](#0-1) 

Each iteration reads a storage slot (`staker_address_ptr.read()`), checks `is_staker_active`, and potentially performs several additional storage reads (`get_staker_staking_power_at_epoch`, `get_public_key_at_epoch`, `get_peer_id_at_epoch`). The cost is strictly proportional to the total number of stakers ever registered, not the number currently active.

The secondary instance is in `src/pool/pool.cairo`, where `calculate_rewards` contains an explicitly acknowledged unbounded loop over a pool member's `pool_member_epoch_balance` trace: [3](#0-2) 

The inline comment reads: *"This loop is unbounded but unlikely to exceed gas limits."* This is the same dismissal pattern seen in the Frax report before the issue was escalated.

---

### Impact Explanation

**Primary (`stakers` Vec / `get_stakers`):** `get_stakers` is a public view function. In Starknet, view functions called from other on-chain contracts consume gas. If the attestation contract or any on-chain consumer calls `get_stakers`, a sufficiently large Vec causes the call to exceed the block gas limit, reverting the transaction. This can permanently prevent reward distribution to all stakers — matching **Permanent freezing of unclaimed yield**.

Even if `get_stakers` is only called off-chain today, the unbounded growth constitutes **Unbounded gas consumption** (medium), and any future on-chain integration immediately inherits the high-severity impact.

**Secondary (`calculate_rewards` loop):** If a pool member's `pool_member_epoch_balance` trace grows large enough (one entry per epoch, bounded by time but unbounded in principle), `claim_rewards` will revert, permanently freezing that member's unclaimed yield.

---

### Likelihood Explanation

- Any permissionless actor can call `stake()` with the minimum stake amount, adding an entry to `self.stakers` that is never removed. There is no cost beyond the minimum stake, which is returned on unstake. An adversary can register and unstake repeatedly across many addresses to bloat the Vec at low net cost.
- The `stakers` Vec is append-only with no cap enforced anywhere in the contract.
- The `calculate_rewards` loop grows naturally over time as pool members remain active across epochs; no adversarial action is required.

---

### Recommendation

1. **`stakers` Vec**: Replace the append-only Vec with a structure that supports O(1) removal (e.g., a swap-and-pop pattern or a doubly-linked list). Remove the staker's entry from `self.stakers` inside `unstake_action`. Alternatively, if `get_stakers` is only needed off-chain, remove it from the on-chain ABI entirely and reconstruct the list from events.
2. **`calculate_rewards` loop**: Enforce a maximum number of unclaimed epochs per `claim_rewards` call, or require callers to pass a checkpoint index so the loop is bounded per invocation.
3. Add a CI check (e.g., a Semgrep rule) that flags any `Vec` storage field whose `push` site has no corresponding removal, and any loop over a storage Vec without a bounded iteration count.

---

### Proof of Concept

**`stakers` Vec bloat:**

1. Attacker deploys N addresses, each calling `stake()` with `min_stake` STRK.
2. Each call appends to `self.stakers` (line 348). [1](#0-0) 
3. Attacker calls `unstake_intent()` then `unstake_action()` on each address, recovering the stake. The Vec entries remain.
4. After enough iterations, `get_stakers(epoch_id)` iterates over all N dead entries plus live stakers, reading multiple storage slots per entry. [4](#0-3) 
5. The transaction gas cost exceeds the block gas limit; `get_stakers` is permanently uncallable on-chain.

**`calculate_rewards` gas exhaustion:**

1. Pool member calls `enter_delegation_pool`, then `add_to_delegation_pool` or `exit_delegation_pool_intent` once per epoch for many epochs.
2. Each epoch appends one entry to `pool_member_epoch_balance` trace. [5](#0-4) 
3. After enough epochs, `claim_rewards` → `calculate_rewards` iterates over all trace entries. [6](#0-5) 
4. The loop exceeds the block gas limit; the member's accumulated yield is permanently frozen.

### Citations

**File:** src/staking/staking.cairo (L347-349)
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

**File:** src/pool/pool.cairo (L721-729)
```text
            let trace = self.pool_member_epoch_balance.entry(pool_member);
            // `cumulative_rewards_trace_idx` should be set to
            // `self.cumulative_rewards_trace_length() + (K - 1)`.
            let pool_member_balance = PoolMemberBalanceTrait::new(
                balance: amount,
                cumulative_rewards_trace_idx: self.cumulative_rewards_trace_length() + 1,
            );
            trace.insert(key: self.get_epoch_plus_k(), value: pool_member_balance);
        }
```

**File:** src/pool/pool.cairo (L857-877)
```text
            // **Note**: The loop iterates over the balance changes in the pool member's balance
            // trace. This loop is unbounded but unlikely to exceed gas limits.
            while entry_to_claim_from < pool_member_trace_length {
                let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
                // If the balance change is after `until_epoch` (and therefore does not affect
                // the current reward computation), exit the loop.
                if pool_member_checkpoint.epoch() >= until_epoch {
                    break;
                }

                // Compute rewards from (inclusive) the previous balance change (or from
                // `from_checkpoint`) to (exclusive) the current entry.
                let to_sigma = self.find_sigma(pool_member_checkpoint, curr_epoch: until_epoch);
                rewards +=
                    compute_rewards_rounded_down(
                        amount: from_balance, interest: to_sigma - from_sigma, :base_value,
                    );
                from_sigma = to_sigma;
                from_balance = pool_member_checkpoint.balance();
                entry_to_claim_from += 1;
            }
```
