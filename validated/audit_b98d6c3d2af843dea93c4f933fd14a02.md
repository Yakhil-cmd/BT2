### Title
Unrestricted `update_rewards` with `disable_rewards=true` Permanently Freezes All Stakers' Consensus Block Rewards — (File: src/staking/staking.cairo)

---

### Summary

`Staking::update_rewards` is a public, permissionless function that accepts a caller-controlled `disable_rewards` boolean. A single global `last_reward_block` storage variable gates all reward distribution for the entire contract. An unprivileged attacker can call `update_rewards(any_active_staker, true)` once per block to consume the block's reward slot without distributing any rewards, permanently preventing every staker from receiving consensus block rewards.

---

### Finding Description

`update_rewards` is exposed via `IStakingRewardsManager` with no role check beyond `general_prerequisites()` (unpaused + non-zero caller): [1](#0-0) 

The function immediately writes `current_block_number` to the **global** `last_reward_block` field: [2](#0-1) 

If `disable_rewards` is `true`, execution returns before any reward calculation or distribution: [3](#0-2) 

`last_reward_block` is a single contract-wide value, not per-staker: [4](#0-3) 

Because the guard asserts `current_block_number > last_reward_block`, once the attacker's call succeeds in a given block, every subsequent legitimate call in that same block reverts with `REWARDS_ALREADY_UPDATED`. No staker can receive consensus block rewards for that block.

The reward distribution path that is blocked is the consensus-phase path in `_update_rewards`, which calls `update_unclaimed_rewards_from_staking_contract` and `claim_from_reward_supplier`: [5](#0-4) 

The pre-consensus attestation path (`update_rewards_from_attestation_contract`) does **not** check `last_reward_block`, so it is unaffected. Only consensus block rewards are frozen.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

By calling `update_rewards(any_active_staker, true)` at the start of every block, an attacker causes the entire consensus reward stream to be permanently suppressed. Stakers' `unclaimed_rewards_own` fields are never incremented, the reward supplier's `unclaimed_rewards` is never updated, and no STRK is ever transferred to stakers or pools for consensus-phase block rewards. The yield is not redirected — it simply never materialises.

---

### Likelihood Explanation

**Medium.** The attacker needs to submit one transaction per block, spending gas with no financial return. On Starknet, per-block gas costs are low enough that a motivated griefer (e.g., a competing validator set, a protocol adversary) can sustain this indefinitely. The attack requires no privileged access, no leaked keys, and no external dependency — only a valid active staker address to pass the `is_staker_active` check, which is publicly readable on-chain.

---

### Recommendation

1. **Restrict the caller**: Add an access control check so that `update_rewards` can only be called by the staker's registered operational address (or a designated rewards-distributor role). This mirrors the pattern already used in `update_rewards_from_attestation_contract`, which asserts `assert_caller_is_attestation_contract`.

2. **Make `last_reward_block` per-staker**: Change `last_reward_block: BlockNumber` to `last_reward_block: Map<ContractAddress, BlockNumber>` so that one staker's reward update cannot block another's.

3. **Remove or gate `disable_rewards`**: If `disable_rewards` is only needed during protocol migrations, gate it behind a privileged role rather than exposing it as a public parameter.

---

### Proof of Concept

```
// Attacker script — run once per block:
staking_contract.update_rewards(
    staker_address = <any_active_staker>,  // publicly readable
    disable_rewards = true
)
// Effect:
//   last_reward_block := current_block_number
//   No rewards calculated, no unclaimed_rewards updated, no STRK transferred.
//
// Any legitimate call in the same block:
staking_contract.update_rewards(staker_address = victim, disable_rewards = false)
// → panics: REWARDS_ALREADY_UPDATED
//
// Repeated every block → all stakers receive zero consensus block rewards indefinitely.
```

The attacker only needs to supply any address that passes: [6](#0-5) 

All active staker addresses are enumerable from the public `stakers` vector: [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L169-170)
```text
        stakers: Vec<ContractAddress>,
        /// Map token address to its decimals.
```

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

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

**File:** src/staking/staking.cairo (L1466-1482)
```text
            let staker_info = self.internal_staker_info(:staker_address);
            let curr_epoch = self.get_current_epoch();
            assert!(
                self.is_staker_active(:staker_address, epoch_id: curr_epoch),
                "{}",
                Error::INVALID_STAKER,
            );

            let staker_pool_info = self.staker_pool_info.entry(staker_address).as_non_mut();
            let (staker_total_strk_balance, staker_total_btc_balance) = self
                .get_staker_total_strk_btc_balance_at_epoch(
                    :staker_address, :staker_pool_info, epoch_id: curr_epoch,
                );
            // Assert staker has non-zero balance.
            // Staker exists with zero balance for the first K epochs after `stake`, then the stake
            // becomes effective.
            assert!(staker_total_strk_balance.is_non_zero(), "{}", Error::INVALID_STAKER);
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

**File:** src/staking/staking.cairo (L2348-2365)
```text
            // Update reward supplier.
            let staker_rewards = staker_own_rewards + commission_rewards;
            // Update total rewards.
            reward_supplier_dispatcher
                .update_unclaimed_rewards_from_staking_contract(
                    rewards: staker_rewards + total_pools_rewards,
                );
            // Claim pools rewards.
            claim_from_reward_supplier(
                :reward_supplier_dispatcher,
                amount: total_pools_rewards,
                token_dispatcher: strk_token_dispatcher(),
            );
            // Update staker rewards.
            staker_info.unclaimed_rewards_own += staker_rewards;

            // Update pools rewards.
            let pool_rewards_list = self.update_pool_rewards(:staker_address, :pools_rewards_data);
```
