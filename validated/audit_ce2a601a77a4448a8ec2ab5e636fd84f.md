### Title
Unprivileged Caller Can Permanently Suppress Per-Block Consensus Rewards for All Stakers via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the Staking contract writes `last_reward_block` to the current block number **before** checking the `disable_rewards` flag. Because the function has no access control beyond a basic pause/zero-address check, any unprivileged caller can invoke `update_rewards(any_valid_staker, disable_rewards: true)` to consume the per-block reward slot without distributing any rewards, permanently preventing all stakers from earning consensus rewards for that block.

### Finding Description
`IStakingRewardsManager::update_rewards` is gated only by `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero. [1](#0-0) 

Inside the function, `last_reward_block` is written unconditionally at line 1485, **before** the `disable_rewards` branch at line 1487: [2](#0-1) 

The guard at the top of the function asserts `current_block_number > last_reward_block`: [3](#0-2) 

Because `last_reward_block` is a single global slot shared by all stakers, once it is written to block N with `disable_rewards: true`, every subsequent call to `update_rewards` in block N reverts with `REWARDS_ALREADY_UPDATED`. The rewards that would have been minted for block N are permanently unclaimable — the slot cannot be reclaimed.

This is structurally identical to the reported pattern: a state variable (`last_reward_block`, analogous to `s_hasVotedByEpochAndTokenId`) is set during an operation that is then short-circuited (the `disable_rewards` early return, analogous to `reset()`), leaving the flag set and blocking all subsequent legitimate operations (other stakers' reward updates, analogous to `deboost()`).

### Impact Explanation
**High — Theft / permanent freezing of unclaimed yield.**

For every block in the consensus-rewards phase, an attacker can front-run the legitimate `update_rewards` call with `update_rewards(any_valid_staker, disable_rewards: true)`. The rewards budgeted for that block by the minting curve are never credited to any staker or pool. Because `last_reward_block` can never be rewound, the loss for that block is permanent. Repeated across many blocks, this constitutes a sustained drain of unclaimed yield from all stakers and delegators. [4](#0-3) 

### Likelihood Explanation
**High.** The attack requires no stake, no privileged role, and no special setup — only gas. The attacker must supply any currently-active staker address (readable from public events or `get_stakers`). The attack can be repeated every block. There is no economic cost beyond transaction fees, and the attacker can selectively target high-value blocks (e.g., blocks with large pending reward accumulations).

### Recommendation
Move `last_reward_block.write(current_block_number)` to **after** the `disable_rewards` guard, so that the slot is only consumed when rewards are actually distributed:

```cairo
// Update last block rewards — only after confirming rewards will be distributed.
if disable_rewards || self.is_pre_consensus() {
    return;
}
self.last_reward_block.write(current_block_number);
// ... rest of reward distribution logic
```

Alternatively, add an access-control check (e.g., `only_app_governor` or a dedicated consensus-caller role) so that `disable_rewards: true` cannot be passed by an unprivileged address.

### Proof of Concept
1. Consensus rewards are active (`consensus_rewards_first_epoch` has been set and the current epoch is ≥ that value).
2. At block N, a legitimate staker's node is about to call `update_rewards(staker_A, disable_rewards: false)`.
3. Attacker front-runs with `update_rewards(staker_A, disable_rewards: true)`.
   - `current_block_number (N) > last_reward_block` — assertion passes.
   - Staker A is active and has non-zero balance — assertions pass.
   - `last_reward_block` is written to N.
   - `disable_rewards == true` → early return; no rewards distributed.
4. The legitimate call arrives: `current_block_number (N) > last_reward_block (N)` is **false** → reverts with `REWARDS_ALREADY_UPDATED`.
5. All stakers and their delegators receive zero rewards for block N. The loss is permanent. [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L1378-1382)
```text
        fn disable_token(ref self: ContractState, token_address: ContractAddress) {
            self.roles.only_security_agent();
            let is_active_opt: Option<(Epoch, bool)> = self.btc_tokens.read(token_address);
            assert!(is_active_opt.is_some(), "{}", Error::TOKEN_NOT_EXISTS);
            let (is_active_first_epoch, is_active) = is_active_opt.unwrap();
```

**File:** src/staking/staking.cairo (L1448-1508)
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
    }
```
