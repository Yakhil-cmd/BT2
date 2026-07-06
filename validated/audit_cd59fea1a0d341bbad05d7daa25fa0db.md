### Title
Unbounded Loop in `calculate_rewards` Can Permanently Freeze Delegator's Unclaimed Yield — (File: `src/pool/pool.cairo`)

---

### Summary

The `calculate_rewards` internal function in `src/pool/pool.cairo` contains an explicitly acknowledged unbounded loop over a pool member's balance-change trace. A delegator who makes many balance changes across many epochs without claiming rewards will accumulate enough trace entries to make any future reward claim revert with out-of-gas, permanently freezing their unclaimed yield with no recovery path.

---

### Finding Description

`calculate_rewards` iterates over every entry in `pool_member_epoch_balance` (the per-member balance trace) that falls between the last claimed checkpoint and the current epoch: [1](#0-0) 

The code itself acknowledges the risk:

> **Note**: The loop iterates over the balance changes in the pool member's balance trace. **This loop is unbounded but unlikely to exceed gas limits.**

Inside each iteration, `find_sigma` is called, which performs additional storage reads via `find_sigma_standard_case` / `find_sigma_edge_cases`: [2](#0-1) 

Each call to `add_to_delegation_pool` or `exit_delegation_pool_intent` in a distinct epoch appends one entry to the trace. There is no cap on how many times a delegator may change their balance, and there is no pagination mechanism in `claim_rewards` or `exit_delegation_pool`. Once the trace is large enough, every attempt to claim rewards or exit the pool will revert due to gas exhaustion, and the delegator has no alternative path to recover their funds. [3](#0-2) 

---

### Impact Explanation

**HIGH — Permanent freezing of unclaimed yield.**

A delegator whose trace has grown beyond the gas limit can never successfully call `claim_rewards` or `exit_delegation_pool`. Their staked principal and all accrued rewards become permanently inaccessible. There is no admin escape hatch or paginated alternative entry point.

---

### Likelihood Explanation

**Medium.** A delegator must make O(hundreds–thousands) of balance-change transactions across distinct epochs without ever claiming rewards. This is a realistic long-term scenario for active delegators who frequently adjust their stake (e.g., partial exits and re-entries) and defer reward claims. No privileged access is required; only normal delegator operations are needed.

---

### Recommendation

1. **Paginate `claim_rewards`**: Accept an optional `max_entries` parameter so the loop can be bounded per call, with the updated `entry_to_claim_from` stored in the checkpoint for the next call.
2. **Enforce a cap on balance-change frequency**: Limit how many trace entries can be added per epoch per pool member (e.g., one entry per epoch).
3. **Alternatively**, merge consecutive trace entries in the same epoch into a single entry at write time, preventing unbounded growth.

---

### Proof of Concept

1. Delegator calls `add_to_delegation_pool` once per epoch for N epochs (N ≈ 500–1000), never calling `claim_rewards`.
2. Each call appends one entry to `pool_member_epoch_balance` for that delegator.
3. Delegator calls `claim_rewards`. `calculate_rewards` enters the while-loop at line 859 and iterates N times, each iteration calling `find_sigma` (multiple storage reads).
4. At sufficiently large N, the transaction exceeds the Starknet gas/step limit and reverts.
5. Every subsequent attempt to claim rewards or exit the pool hits the same revert. The delegator's yield is permanently frozen. [1](#0-0)

### Citations

**File:** src/pool/pool.cairo (L844-877)
```text
            let pool_member_trace = self.pool_member_epoch_balance.entry(pool_member);
            // Note: `until_epoch` is the current epoch.
            let until_epoch = until_checkpoint.epoch();

            let mut rewards = 0;

            let pool_member_trace_length = pool_member_trace.length();

            let mut from_sigma = self.find_sigma(from_checkpoint, curr_epoch: until_epoch);
            let mut from_balance = from_checkpoint.balance();

            let base_value = self.staking_rewards_base_value.read();

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
