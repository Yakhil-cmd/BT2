### Title
Unpermissioned `update_rewards` Allows Any Caller to Permanently Freeze Staker Block Rewards - (File: `src/staking/staking.cairo`)

---

### Summary
`IStakingRewardsManager::update_rewards` in the `Staking` contract has no caller access control. Any address can invoke it with `disable_rewards: true` against any valid staker, consuming the global `last_reward_block` slot for the current block without distributing any rewards. Because the slot is global and can only be consumed once per block, an attacker who does this every block permanently prevents all stakers from ever receiving consensus block rewards.

---

### Finding Description
`StakingRewardsManagerImpl::update_rewards` is a public, permissionless function:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks pause flag
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    // Update last block rewards.
    self.last_reward_block.write(current_block_number);   // global slot consumed

    if disable_rewards || self.is_pre_consensus() {
        return;                                           // exits without distributing rewards
    }
    ...
```

`last_reward_block` is a **global** storage variable shared across all stakers. Once it is written to the current block number, the `REWARDS_ALREADY_UPDATED` assertion prevents any further call to `update_rewards` in the same block. The caller-controlled `disable_rewards` flag causes the function to return immediately after consuming the slot, skipping the entire reward distribution path.

There is no `assert_caller_is_*` check, no role guard, and no restriction on who may supply the `disable_rewards` flag.

---

### Impact Explanation
An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` at the first transaction of every block:

1. Consumes the global `last_reward_block` slot for that block.
2. Causes the function to return before `_update_rewards` is reached, so no staker or pool receives block rewards.
3. Blocks every legitimate call to `update_rewards` for the remainder of that block.

Repeated across every block, this permanently freezes all unclaimed consensus block rewards for every staker and every delegation pool in the protocol. The attacker needs only a valid staker address (publicly readable from `NewStaker` events) and the gas cost of one transaction per block.

**Impact: Permanent freezing of unclaimed yield** — matches the allowed High impact category.

---

### Likelihood Explanation
- Entry point is fully public; no privileged role, no staking deposit, no prior relationship with the protocol is required.
- Valid staker addresses are trivially obtained from on-chain events.
- The cost is one cheap transaction per block; the attacker gains nothing but the protocol loses all consensus reward distribution indefinitely.
- Likelihood: **High**.

---

### Recommendation
Restrict `update_rewards` to a trusted caller. The natural caller is the attestation contract or a designated keeper role. For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.roles.only_rewards_manager();   // add a dedicated role, or
    // assert!(get_caller_address() == self.attestation_contract.read(), ...);
    ...
```

Alternatively, remove the `disable_rewards` parameter from the public interface entirely and handle the pre-consensus / disable logic internally, so no external caller can suppress reward distribution.

---

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. Attacker reads any live staker address `S` from a `NewStaker` event.
3. At the first transaction slot of block `N`, attacker calls:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. `last_reward_block` is written to `N`; the function returns without distributing rewards.
5. Any legitimate call to `update_rewards` in block `N` reverts with `REWARDS_ALREADY_UPDATED`.
6. Stakers and pools receive zero block rewards for block `N`.
7. Attacker repeats step 3 every block → all consensus block rewards are permanently frozen.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2)

### Citations

**File:** src/staking/staking.cairo (L1448-1507)
```text
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
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

            // Assert staker exists and active.
            // Staker is considered to exist from the moment of `stake` (when `InternalStakerInfo`
            // struct is created) until the calling to `unstake_action` (when `InternalStakerInfo`
            // struct is deleted).
            // Staker remains active until the intent period begins, i.e. K epochs after
            // `unstake_intent` is called.
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

**File:** src/staking/interface.cairo (L303-311)
```text
#[starknet::interface]
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```
