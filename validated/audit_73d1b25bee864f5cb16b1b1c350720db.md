### Title
Unprivileged Caller Can Permanently Freeze Consensus-Phase Rewards via Unvalidated `disable_rewards` Parameter in `update_rewards` — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract accepts a caller-supplied `disable_rewards: bool` parameter with no access control and no validation against any stored state variable. Because the function unconditionally advances the global `last_reward_block` slot **before** checking `disable_rewards`, any unprivileged address can call `update_rewards(valid_staker, true)` once per block to consume that block's reward slot without distributing rewards, permanently denying all stakers their consensus-phase yield.

---

### Finding Description

`IStakingRewardsManager::update_rewards` is a public function gated only by `general_prerequisites`, which checks that the contract is unpaused and the caller is non-zero — no role restriction exists. [1](#0-0) 

The function accepts two parameters: `staker_address` (validated against stored state — staker must exist, be active, and have non-zero balance) and `disable_rewards` (a boolean with **no validation against any stored state variable**). [2](#0-1) 

Critically, the function writes `current_block_number` to the global `last_reward_block` storage variable **before** the `disable_rewards` guard: [3](#0-2) 

Because the function asserts `current_block_number > self.last_reward_block.read()` at the top, only one successful call is possible per block. An attacker who calls `update_rewards(any_valid_staker, true)` in every block will:

1. Pass all staker-existence checks (using any legitimately staked address).
2. Advance `last_reward_block` to the current block.
3. Hit the early-return branch — no rewards are calculated or distributed.
4. Block every legitimate call in that block with `REWARDS_ALREADY_UPDATED`. [4](#0-3) 

The analog to the external report is direct: just as `acceptedCurrency` in the Marketplace was never validated against the stored contract currency, `disable_rewards` here is never validated against any stored authorization state. A user-supplied parameter silently overrides the intended protocol behavior.

---

### Impact Explanation

In the consensus-rewards phase, `update_rewards` is the sole mechanism by which stakers accumulate `unclaimed_rewards_own` and pools receive their share. If the attack is sustained, `staker_info.unclaimed_rewards_own` is never incremented for any staker, and `update_pool_rewards` is never called. This constitutes **permanent freezing of unclaimed yield** for every staker and delegator in the protocol for as long as the attacker continues. [5](#0-4) 

---

### Likelihood Explanation

**Medium.** The attack requires one transaction per block — cheap on Starknet. The entry point is fully permissionless (any non-zero address). The attacker needs only to know one valid, active staker address (publicly observable from `NewStaker` events). No privileged access, no leaked key, no external dependency is required.

---

### Recommendation

Add access control to `update_rewards` so that only an authorized caller (e.g., the consensus layer contract, or a dedicated `REWARDS_MANAGER_ROLE`) may invoke it. Alternatively, validate `disable_rewards` against a stored state variable — for example, derive it internally from whether the staker met its consensus obligations rather than accepting it as a caller-supplied argument.

---

### Proof of Concept

1. Attacker observes any valid, active `staker_address` from on-chain events.
2. Each block, attacker calls:
   ```
   staking.update_rewards(staker_address, disable_rewards: true)
   ```
3. `last_reward_block` is set to the current block number; the function returns early.
4. Any legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. No staker ever accumulates `unclaimed_rewards_own`; no pool ever receives rewards.
6. All unclaimed yield is permanently frozen for the duration of the attack. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L1448-1452)
```text
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
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
