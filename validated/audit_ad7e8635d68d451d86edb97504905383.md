### Title
Unprivileged Caller Can Permanently Deny Consensus Block Rewards via `update_rewards(disable_rewards: true)` - (File: `src/staking/staking.cairo`)

### Summary
`update_rewards` in the Staking contract is callable by any address and accepts a caller-controlled `disable_rewards: bool` parameter. When called with `disable_rewards: true`, the function writes the current block number to `last_reward_block` **before** checking the flag, consuming the single per-block reward slot without distributing any rewards. Any subsequent legitimate call in the same block reverts with `REWARDS_ALREADY_UPDATED`. An attacker can call this every block to permanently deny all stakers their consensus block rewards at the cost of only their own gas.

### Finding Description

`update_rewards` in `StakingRewardsManagerImpl` has no caller authorization check. The only gate is that `current_block_number > last_reward_block`, which is a global, per-block slot shared across all stakers. [1](#0-0) 

The critical ordering flaw is that `last_reward_block` is committed to storage **before** the `disable_rewards` branch is evaluated: [2](#0-1) 

```cairo
// Update last block rewards.
self.last_reward_block.write(current_block_number);   // slot consumed here

if disable_rewards || self.is_pre_consensus() {
    return;   // rewards skipped, but slot is already gone
}
```

Any address can therefore call:
```
update_rewards(staker_address=<any_valid_active_staker>, disable_rewards=true)
```

This atomically:
1. Passes all precondition checks (staker exists, is active, has non-zero balance).
2. Writes `last_reward_block = current_block_number`.
3. Returns immediately without distributing rewards.

Every subsequent call to `update_rewards` in the same block — including the legitimate consensus call — hits the `REWARDS_ALREADY_UPDATED` assertion and reverts. [3](#0-2) 

Because `last_reward_block` is a single global storage slot (not per-staker), one attacker transaction per block silences reward distribution for **all** stakers simultaneously. [4](#0-3) 

### Impact Explanation

Every block in which the attacker fires this transaction, the entire staker set receives zero consensus block rewards. The rewards are never generated — they are permanently lost, not deferred. This constitutes **permanent freezing / theft of unclaimed yield** for all stakers and their delegators, matching the High-severity impact tier.

### Likelihood Explanation

- No privileged key or special role is required; any EOA or contract can call `update_rewards`.
- The only precondition is supplying any valid, active staker address — trivially obtained from on-chain `NewStaker` events.
- The attacker pays only their own transaction fee per block; on Starknet this is denominated in STRK, making a sustained campaign economically feasible for a motivated adversary.
- The attack is front-running-free in the sense that the attacker does not need to beat a specific transaction; they simply need to submit one transaction per block before the legitimate consensus caller does.

### Recommendation

Add an explicit caller authorization check to `update_rewards`, restricting it to the attestation contract, a designated consensus caller, or the staker themselves:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
+   assert!(
+       get_caller_address() == self.attestation_contract.read()
+           || get_caller_address() == staker_address,
+       "{}",
+       Error::UNAUTHORIZED_CALLER,
+   );
    self.general_prerequisites();
    ...
```

Alternatively, move the `last_reward_block.write` to **after** the `disable_rewards` guard so that a no-op call does not consume the per-block slot.

### Proof of Concept

1. Staker Alice stakes and is active with non-zero balance.
2. Attacker (any address) monitors the chain and, at the start of each new block, submits:
   ```
   staking.update_rewards(staker_address=Alice, disable_rewards=true)
   ```
3. `last_reward_block` is set to the current block number; no rewards are distributed.
4. The legitimate consensus `update_rewards` call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. Alice and all other stakers receive zero block rewards for that block.
6. Repeated every block, this permanently denies all consensus rewards to the entire staker set. [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1510)
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

    #[generate_trait]
```
