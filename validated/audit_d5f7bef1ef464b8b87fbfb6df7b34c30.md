### Title
Unrestricted `update_rewards` with `disable_rewards: true` Allows Any Caller to Permanently Block Consensus Reward Distribution for All Stakers — (File: `src/staking/staking.cairo`)

---

### Summary

The `IStakingRewardsManager::update_rewards` function is publicly callable by any address with no access control. It accepts a `disable_rewards: bool` parameter. When called with `disable_rewards: true`, it consumes the global per-block reward slot (`last_reward_block`) without distributing any rewards. An unprivileged attacker can call this every block for any valid staker, permanently preventing all stakers from ever receiving consensus block rewards.

---

### Finding Description

`update_rewards` is exposed as a public external function under `#[abi(embed_v0)]`: [1](#0-0) 

The function enforces a single-call-per-block invariant using a **global** `last_reward_block` storage variable: [2](#0-1) 

Immediately after passing this check, it writes the current block number to storage: [3](#0-2) 

Then, if `disable_rewards` is `true`, it returns early **without distributing any rewards**: [4](#0-3) 

The `last_reward_block` field is a single global variable shared across all stakers: [5](#0-4) 

**Attack path:**

1. Attacker identifies any active staker `S` with non-zero balance (trivially available on-chain via `get_stakers` or events).
2. In every block, attacker calls `update_rewards(S, disable_rewards: true)`.
3. The call passes the `last_reward_block` check (new block), writes `last_reward_block = current_block`, then returns early — no rewards distributed.
4. Any subsequent call to `update_rewards` in the same block by any party (staker, operator, or protocol) fails with `REWARDS_ALREADY_UPDATED`.
5. No staker receives consensus block rewards for that block.

The attacker requires no special role, no stake, and no funds beyond gas. The only precondition is knowing a valid active staker address with non-zero balance, which is public on-chain.

---

### Impact Explanation

`update_rewards` is the sole mechanism for distributing consensus block rewards to stakers and their delegation pools: [6](#0-5) 

By consuming the global `last_reward_block` slot every block with `disable_rewards: true`, the attacker causes **permanent freezing of unclaimed yield** for all stakers and pool members. No rewards accumulate in `unclaimed_rewards_own` for stakers, and no rewards are forwarded to delegation pools via `update_pool_rewards`. This matches the **High** impact category: *Permanent freezing of unclaimed yield*.

---

### Likelihood Explanation

- The function is fully public with no access control.
- The attacker needs only a valid active staker address — trivially obtained from on-chain data.
- On Starknet, gas costs are low, making sustained per-block griefing economically viable.
- No profit motive is required; the attack is purely destructive.

---

### Recommendation

Restrict `update_rewards` to authorized callers only. The `disable_rewards: true` path appears intended for protocol-internal use (e.g., block tracking without reward distribution during transitions). Options:

1. **Restrict to staker or operator only**: Require `get_caller_address() == staker_address` or a registered operational address.
2. **Restrict `disable_rewards: true` to a privileged role**: Only allow `disable_rewards: true` from the attestation contract or a governance-controlled address.
3. **Separate the two paths**: Split into a privileged `update_block_tracking()` (no rewards) and a permissioned `update_rewards()` (with rewards), each with appropriate access control.

---

### Proof of Concept

```
// Attacker script (pseudocode, runs every block):
let staker_S = any_active_staker_from_chain();  // e.g., read from NewStaker events
staking_contract.update_rewards(staker_S, disable_rewards: true);
// Result: last_reward_block = current_block, no rewards distributed.
// All subsequent update_rewards calls in this block revert with REWARDS_ALREADY_UPDATED.
// Stakers accumulate zero unclaimed_rewards_own for this block.
// Pool members receive zero rewards forwarded to their pools.
```

The attacker repeats this every block. All stakers and pool members are permanently denied consensus rewards for as long as the attack continues, constituting a sustained freeze of unclaimed yield.

### Citations

**File:** src/staking/staking.cairo (L186-187)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
```

**File:** src/staking/staking.cairo (L1447-1450)
```text
    #[abi(embed_v0)]
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
```

**File:** src/staking/staking.cairo (L1453-1458)
```text
            let current_block_number = starknet::get_block_number();
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
                Error::REWARDS_ALREADY_UPDATED,
            );
```

**File:** src/staking/staking.cairo (L1484-1485)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);
```

**File:** src/staking/staking.cairo (L1487-1489)
```text
            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

**File:** src/staking/staking.cairo (L1491-1507)
```text
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
