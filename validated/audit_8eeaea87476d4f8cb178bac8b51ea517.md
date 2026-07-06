### Title
Missing Access Control on `update_rewards` Allows Any Caller to Steal or Freeze Block Rewards - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in the staking contract is specified to be callable only by the Starknet sequencer, but the implementation contains no access control enforcement. Any unprivileged caller — including a staker — can invoke it, manipulating the global `last_reward_block` state variable. This either redirects block rewards to the attacker's own staker or permanently freezes yield for the legitimately designated staker for that block.

### Finding Description

The protocol specification for `update_rewards` explicitly states:

> **access control**: Only starkware sequencer.

However, the implementation in `StakingRewardsManagerImpl` performs no such check: [1](#0-0) 

The function only calls `self.general_prerequisites()` (a pause check) and then immediately proceeds to validate the `staker_address` parameter and write to the global `last_reward_block` storage variable: [2](#0-1) 

`last_reward_block` is a single global slot shared across all stakers: [3](#0-2) 

The guard that prevents double-distribution per block is: [4](#0-3) 

Because `last_reward_block` is written unconditionally — even when `disable_rewards: true` causes an early return before any rewards are computed — a single attacker call per block permanently exhausts the one-call-per-block budget for the entire protocol. [2](#0-1) 

### Impact Explanation

**Attack vector A — Theft of unclaimed yield (High):**

An attacker who is a registered staker calls:
```
update_rewards(staker_address: attacker_staker, disable_rewards: false)
```
The attacker's staker receives the full block reward (proportional to their stake). `last_reward_block` is set to the current block. The sequencer's subsequent call for the legitimately designated staker reverts with `REWARDS_ALREADY_UPDATED`. The designated staker earns zero yield for that block. Repeated every block, this constitutes sustained theft of unclaimed yield from other stakers.

**Attack vector B — Permanent freezing of unclaimed yield (High):**

An attacker (who need not be a staker themselves) calls:
```
update_rewards(staker_address: any_valid_staker, disable_rewards: true)
```
`last_reward_block` is updated but no rewards are distributed to anyone. The sequencer cannot call `update_rewards` again in that block. All stakers lose their yield for that block with zero cost to the attacker beyond gas.

The pool reward pipeline is also affected: `update_rewards_from_staking_contract` on pool contracts is only triggered from within `_update_rewards`, so pool delegators also lose their yield. [5](#0-4) 

### Likelihood Explanation

- The function is publicly callable with no role gate.
- The attacker only needs to know any valid, active staker address (all staker addresses are public on-chain via the `stakers` vector and emitted events).
- The minimum stake requirement is the only barrier to Attack Vector A; Attack Vector B requires no stake at all.
- The attack is repeatable every block at negligible cost. [6](#0-5) 

### Recommendation

Add a sequencer-only access control guard at the top of `update_rewards`, analogous to how `update_rewards_from_attestation_contract` enforces `CALLER_IS_NOT_ATTESTATION_CONTRACT`: [7](#0-6) 

Concretely, introduce a stored `sequencer_address` (or use an existing role) and assert `get_caller_address() == self.sequencer_address.read()` as the first statement in `update_rewards`.

### Proof of Concept

```
// Attacker is a registered staker with minimum stake.
// Block N begins. Sequencer has not yet called update_rewards.

// Step 1: Attacker front-runs the sequencer.
staking.update_rewards(
    staker_address: attacker_address,
    disable_rewards: false,   // attacker collects block rewards
);
// last_reward_block is now N.

// Step 2: Sequencer attempts to distribute rewards to the designated staker.
staking.update_rewards(
    staker_address: designated_staker,
    disable_rewards: false,
);
// PANICS: REWARDS_ALREADY_UPDATED
// designated_staker earns zero yield for block N.
// Attacker's staker earned the full block reward.
```

Repeated each block, the attacker continuously siphons block rewards away from the legitimately designated stakers, constituting ongoing theft of unclaimed yield.

### Citations

**File:** src/staking/staking.cairo (L168-170)
```text
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
        /// Map token address to its decimals.
```

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1380-1423)
```text
            let is_active_opt: Option<(Epoch, bool)> = self.btc_tokens.read(token_address);
            assert!(is_active_opt.is_some(), "{}", Error::TOKEN_NOT_EXISTS);
            let (is_active_first_epoch, is_active) = is_active_opt.unwrap();
            let curr_epoch = self.get_current_epoch();
            assert!(curr_epoch >= is_active_first_epoch, "{}", Error::INVALID_EPOCH);
            assert!(is_active, "{}", Error::TOKEN_ALREADY_DISABLED);
            let next_is_active_first_epoch = self.get_epoch_plus_k();
            self.btc_tokens.write(token_address, (next_is_active_first_epoch, false));
            self.emit(TokenManagerEvents::TokenDisabled { token_address });
        }
    }

    #[abi(embed_v0)]
    impl StakingAttestationImpl of IStakingAttestation<ContractState> {
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);

            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
            // Get current epoch data.
            let (strk_epoch_rewards, btc_epoch_rewards) = reward_supplier_dispatcher
                .calculate_current_epoch_rewards();
            let (strk_total_stake, btc_total_stake) = self.get_current_total_staking_power();
            let staker_pool_info = self.staker_pool_info.entry(staker_address).as_non_mut();
            let curr_epoch = self.get_current_epoch();
            self
                ._update_rewards(
                    :staker_address,
                    strk_total_rewards: strk_epoch_rewards,
                    btc_total_rewards: btc_epoch_rewards,
                    :strk_total_stake,
                    :btc_total_stake,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
        }
```

**File:** src/staking/staking.cairo (L1449-1489)
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
