### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Freeze Staker Yield - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in the `StakingRewardsManagerImpl` is documented to be callable only by the Starkware sequencer, but the implementation contains no caller validation. Any unprivileged address can call `update_rewards` with `disable_rewards: true` to consume the per-block reward slot, permanently preventing the legitimate sequencer call from distributing rewards for that block to all stakers.

### Finding Description

The `IStakingRewardsManager` interface exposes `update_rewards`, which is the consensus-era reward distribution entry point. The specification explicitly restricts this function:

> **access control**: Only starkware sequencer. [1](#0-0) 

The implementation, however, performs no such check. The only guards are:

1. `general_prerequisites()` — checks the contract is not paused.
2. A block-level deduplication guard: `current_block_number > self.last_reward_block.read()`.
3. Staker existence and activity checks. [2](#0-1) 

After passing these checks, the function unconditionally writes `current_block_number` into `last_reward_block` **before** branching on `disable_rewards`: [3](#0-2) 

`last_reward_block` is a single global storage variable shared across all stakers. Once it is set to the current block number, every subsequent call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`, regardless of which staker is targeted. [4](#0-3) 

### Impact Explanation

An attacker calls `update_rewards(any_valid_staker, disable_rewards: true)` at block N before the sequencer does. This:

1. Passes all guards (contract active, block N not yet processed, staker valid).
2. Writes `last_reward_block = N`.
3. Returns immediately without distributing any rewards (`disable_rewards == true`).

The sequencer's subsequent calls for block N — for every staker — all revert with `REWARDS_ALREADY_UPDATED`. No staker receives consensus block rewards for block N. Repeating this every block permanently freezes all unclaimed consensus yield.

This matches the allowed impact: **High — Permanent freezing of unclaimed yield**.

### Likelihood Explanation

- The function is publicly callable with no role or address restriction.
- The attacker only needs to submit a transaction before the sequencer in the same block — a standard front-running scenario on Starknet.
- The cost is a single gas-cheap transaction per block.
- No special privileges, leaked keys, or external dependencies are required.
- The attack is fully automated and sustainable indefinitely.

### Recommendation

Add an explicit sequencer-only access control check at the top of `update_rewards`, analogous to how `update_rewards_from_attestation_contract` restricts its caller to the attestation contract:

```cairo
fn update_rewards_from_attestation_contract(...) {
    ...
    assert!(
        get_caller_address() == self.attestation_contract.read(),
        "{}",
        Error::CALLER_IS_NOT_ATTESTATION_CONTRACT,
    );
``` [5](#0-4) 

Store the authorized sequencer address in contract storage during construction and assert `get_caller_address() == self.sequencer_address.read()` as the first statement in `update_rewards`.

### Proof of Concept

```
Block N arrives.

1. Attacker submits:
   update_rewards(staker_address = <any active staker>, disable_rewards = true)

   → general_prerequisites() passes (contract not paused)
   → current_block_number (N) > last_reward_block (N-1) → passes
   → staker exists and is active → passes
   → last_reward_block.write(N)          ← slot consumed
   → disable_rewards == true → return    ← no rewards distributed

2. Sequencer submits (same block N):
   update_rewards(staker_address = staker_A, disable_rewards = false)

   → current_block_number (N) > last_reward_block (N) → FALSE
   → PANIC: REWARDS_ALREADY_UPDATED

3. All stakers lose consensus block rewards for block N.
   Repeating step 1 every block permanently freezes all yield.
``` [6](#0-5)

### Citations

**File:** docs/spec.md (L1643-1645)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1360-1410)
```text
                .entry(token_address)
                .insert(key: STARTING_EPOCH, value: Zero::zero());
            self.emit(TokenManagerEvents::TokenAdded { token_address });
        }

        fn enable_token(ref self: ContractState, token_address: ContractAddress) {
            self.roles.only_token_admin();
            let is_active_opt: Option<(Epoch, bool)> = self.btc_tokens.read(token_address);
            assert!(is_active_opt.is_some(), "{}", Error::TOKEN_NOT_EXISTS);
            let (is_active_first_epoch, is_active) = is_active_opt.unwrap();
            let curr_epoch = self.get_current_epoch();
            assert!(curr_epoch >= is_active_first_epoch, "{}", Error::INVALID_EPOCH);
            assert!(!is_active, "{}", Error::TOKEN_ALREADY_ENABLED);
            let next_is_active_first_epoch = self.get_epoch_plus_k();
            self.btc_tokens.write(token_address, (next_is_active_first_epoch, true));
            self.emit(TokenManagerEvents::TokenEnabled { token_address });
        }

        fn disable_token(ref self: ContractState, token_address: ContractAddress) {
            self.roles.only_security_agent();
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
```

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
