### Title
Unprivileged Caller Can Permanently Freeze Consensus Block Rewards for All Stakers via `update_rewards` Missing Access Control - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in `StakingRewardsManagerImpl` is documented as restricted to "Only starkware sequencer" but contains no on-chain caller validation. Any unprivileged address can call it with `disable_rewards: true` every block, consuming the global `last_reward_block` slot and permanently preventing the legitimate sequencer from distributing consensus rewards to any staker.

### Finding Description
`IStakingRewardsManager::update_rewards` is the consensus-era reward distribution entry point. The spec explicitly states its access control is "Only starkware sequencer." [1](#0-0) 

However, the implementation performs no such check: [2](#0-1) 

The function reads and writes a single **global** `last_reward_block` storage variable: [3](#0-2) 

Because `last_reward_block` is a contract-wide singleton (not per-staker), a single call to `update_rewards(any_valid_staker, disable_rewards: true)` in block N:
1. Passes all assertions (staker exists, is active, block is new).
2. Writes `last_reward_block = N`.
3. Returns early without distributing any rewards (`disable_rewards || self.is_pre_consensus()` branch).

Any subsequent call in the same block — including the legitimate sequencer's call — reverts with `REWARDS_ALREADY_UPDATED`. [4](#0-3) 

The test suite confirms no caller restriction exists: `update_rewards` is invoked throughout tests without any `cheat_caller_address` setup: [5](#0-4) 

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

An attacker who calls `update_rewards(valid_staker, disable_rewards: true)` at the start of every block prevents the sequencer from ever distributing consensus block rewards. Because `last_reward_block` is global, a single griefing call per block blocks reward distribution for **all** stakers and all their delegation pools. Stakers and delegators accumulate zero `unclaimed_rewards_own` indefinitely. The attack is permanent as long as the attacker continues (one tx per block), and the attacker has no profit motive — pure griefing.

### Likelihood Explanation
**High.** The entry point is fully public, requires no special role, no token approval, and no prior state setup beyond providing any existing valid staker address (all staker addresses are observable on-chain). The only cost is gas per block. A single motivated attacker can sustain this indefinitely.

### Recommendation
Add a caller check at the top of `update_rewards` that asserts `get_caller_address()` equals the configured starkware sequencer address (stored in contract state), mirroring the pattern used for `update_rewards_from_attestation_contract`: [6](#0-5) 

Store the sequencer address during initialization and assert it on every call, or introduce a dedicated `CALLER_IS_NOT_SEQUENCER` error analogous to `CALLER_IS_NOT_ATTESTATION_CONTRACT`. [7](#0-6) 

### Proof of Concept
1. Deploy the system with consensus rewards active (epoch ≥ `consensus_rewards_first_epoch`).
2. Staker A stakes and waits K epochs so their balance is effective.
3. Attacker (any EOA) calls `update_rewards(staker_A_address, disable_rewards: true)` at block B.
   - Passes: `B > last_reward_block`, staker exists and is active, balance non-zero.
   - Sets `last_reward_block = B`, returns without distributing rewards.
4. Sequencer calls `update_rewards(staker_A_address, disable_rewards: false)` at block B → reverts `REWARDS_ALREADY_UPDATED`.
5. Repeat step 3 every block. Staker A's `unclaimed_rewards_own` never increases. All delegation pool balances remain zero. Yield is permanently frozen. [8](#0-7)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
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

**File:** src/staking/tests/test.cairo (L3877-3877)
```text
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
```
