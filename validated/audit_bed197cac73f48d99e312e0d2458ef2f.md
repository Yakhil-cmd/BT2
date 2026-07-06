### Title
Unvalidated `disable_rewards` Parameter in `update_rewards` Allows Any Caller to Permanently Deny Staker Yield — (File: `src/staking/staking.cairo`)

---

### Summary
The public `update_rewards` function in `staking.cairo` has no caller access control and accepts an attacker-controlled `disable_rewards: bool` parameter. When set to `true`, the function updates the global `last_reward_block` state variable and returns early without distributing any rewards. Because `last_reward_block` is global and the function enforces a strict "one call per block" invariant, an unprivileged attacker can call `update_rewards(victim_staker, true)` every block to permanently deny all consensus-era yield to any staker.

---

### Finding Description

`update_rewards` is gated only by `general_prerequisites()`, which checks the pause flag and that the caller is non-zero — no role or identity check is performed. [1](#0-0) 

The function then writes the current block number into the **global** `last_reward_block` storage slot unconditionally, before the `disable_rewards` branch: [2](#0-1) 

If `disable_rewards` is `true`, the function returns immediately after that write, skipping all reward calculation and distribution: [3](#0-2) 

Because `last_reward_block` is a single global slot (not per-staker), the one-call-per-block guard now blocks any legitimate call for the remainder of that block: [4](#0-3) 

An attacker who front-runs the legitimate `update_rewards` call every block with `disable_rewards: true` causes the staker to receive zero rewards for every block, with no recovery path — the missed block rewards are simply never credited.

---

### Impact Explanation

**High — Permanent freezing / theft of unclaimed yield.**

In the consensus-rewards phase (`is_pre_consensus() == false`), `update_rewards` is the sole mechanism by which per-block STRK (and BTC) rewards are credited to a staker's `unclaimed_rewards_own` and forwarded to delegation pools. Suppressing it every block means the staker and all its delegators accumulate zero yield indefinitely. The lost rewards are never re-queued; they are simply not minted/credited for those blocks.

---

### Likelihood Explanation

**High.** The attack requires no privileged role, no leaked key, and no external dependency. The only cost is gas for one transaction per block. On Starknet, block times are short and gas is cheap, making sustained griefing economically viable. A competitor staker or a malicious delegator of a rival pool has a direct financial incentive to execute this attack.

---

### Recommendation

1. **Restrict the caller**: `update_rewards` should only be callable by a trusted consensus layer address (e.g., the attestation contract or a designated operator role). Add an `assert_caller_is_authorized()` guard analogous to `assert_caller_is_attestation_contract`.
2. **Remove or gate `disable_rewards`**: If the parameter is needed for internal migration flows, it should be callable only by a privileged role (e.g., `only_app_governor`), or the flag should be derived from on-chain state rather than supplied by the caller.
3. **Per-staker `last_reward_block`**: Consider making the "already updated" guard per-staker rather than global, so that a suppressed call for one staker does not block legitimate calls for others.

---

### Proof of Concept

```
// Attacker script — run once per block, before the legitimate sequencer call

loop every block:
    staking_contract.update_rewards(
        staker_address = <victim>,   // any valid, active staker
        disable_rewards = true       // no validation; accepted by the contract
    )
    // Effect:
    //   last_reward_block := current_block   (global write)
    //   returns early — zero rewards credited
    //   any subsequent call this block reverts with REWARDS_ALREADY_UPDATED
```

Concrete entry path:
1. Attacker (any EOA) calls `update_rewards(victim_staker, true)` at block N.
2. `general_prerequisites()` passes (contract not paused, caller non-zero). [5](#0-4) 
3. `current_block_number > last_reward_block` passes (first call this block).
4. `last_reward_block` is written to N. [6](#0-5) 
5. `disable_rewards == true` → early return, no rewards distributed. [7](#0-6) 
6. Legitimate call at block N reverts: `REWARDS_ALREADY_UPDATED`.
7. Repeat at block N+1 → staker earns zero yield for every block.

### Citations

**File:** src/staking/staking.cairo (L1449-1458)
```text
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
            let current_block_number = starknet::get_block_number();
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
                Error::REWARDS_ALREADY_UPDATED,
            );
```

**File:** src/staking/staking.cairo (L1484-1507)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }

            // Get current block data and update rewards.
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
            let (strk_block_rewards, btc_block_rewards) = self
                .calculate_block_rewards(:reward_supplier_dispatcher, :curr_epoch);
            self
                ._update_rewards(
                    :staker_address,
                    strk_total_rewards: strk_block_rewards,
                    btc_total_rewards: btc_block_rewards,
                    strk_total_stake: staker_total_strk_balance,
                    btc_total_stake: staker_total_btc_balance,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
        }
```

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
