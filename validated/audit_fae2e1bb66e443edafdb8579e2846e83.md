### Title
Missing Caller Restriction on `update_rewards` Allows Any Address to Hijack Block Reward Distribution - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the Staking contract is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can invoke it, choosing which staker receives block rewards and consuming the single per-block reward slot, permanently denying rewards to all other stakers.

### Finding Description
The specification explicitly restricts `update_rewards` to the Starkware sequencer:

> **Access control:** Only starkware sequencer. [1](#0-0) 

The implementation, however, performs no such check. After `general_prerequisites()` (which only verifies the pause flag) and a block-number guard, the function immediately writes `last_reward_block` and distributes rewards: [2](#0-1) 

The `last_reward_block` guard enforces that only **one** `update_rewards` call succeeds per block: [3](#0-2) 

Once that single slot is consumed, the sequencer's own call reverts with `REWARDS_ALREADY_UPDATED`. The attacker fully controls which staker is credited for that block and whether `disable_rewards` suppresses the payout entirely.

### Impact Explanation
**High — Theft of unclaimed yield / Permanent freezing of unclaimed yield.**

Two concrete attack paths:

1. **Yield theft**: An attacker who is a registered staker calls `update_rewards(attacker_staker, disable_rewards: false)` at the start of every block. They receive their proportional block reward every block. All other stakers receive zero rewards indefinitely, because the per-block slot is always consumed before the sequencer can act on their behalf.

2. **Yield freeze**: An attacker (need not be a staker) calls `update_rewards(any_valid_staker, disable_rewards: true)` every block. `last_reward_block` is updated but no rewards are minted or transferred. Every staker's `unclaimed_rewards_own` is permanently frozen at its current value. [4](#0-3) 

### Likelihood Explanation
The function is public and requires no special role, token balance, or prior state beyond a valid `staker_address`. A single EOA can front-run the sequencer on every block with a trivially cheap transaction. On Starknet, where transaction ordering within a block is sequencer-controlled, a determined attacker can consistently win the race by submitting the call at the start of each block.

### Recommendation
Add an explicit caller check mirroring the pattern used for other privileged callbacks in the same contract. Store the authorized sequencer address in storage (or derive it from a role) and assert it at the top of `update_rewards`:

```cairo
fn update_rewards(ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool) {
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    self.general_prerequisites();
    // ...
}
```

This mirrors the pattern already used for `update_rewards_from_attestation_contract`: [5](#0-4) 

### Proof of Concept

1. Deploy the system and advance past `consensus_rewards_first_epoch` so rewards are active.
2. As an unprivileged address (or as a registered staker), call:
   ```
   IStakingRewardsManagerDispatcher { contract_address: staking }.update_rewards(
       staker_address: attacker_staker,
       disable_rewards: false,
   );
   ```
3. Observe that `last_reward_block` is now set to the current block and the attacker's staker has `unclaimed_rewards_own` increased.
4. The sequencer's subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeat every block: all other stakers accumulate zero rewards while the attacker's staker accrues the full block reward each block. [6](#0-5)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1394-1401)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
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
