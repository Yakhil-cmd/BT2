### Title
Missing Access Control on `update_rewards` Allows Any Caller to Monopolize Per-Block Reward Slots - (File: src/staking/staking.cairo)

### Summary

The `update_rewards` function in the staking contract is specified to be callable only by the Starkware sequencer, but the implementation enforces no such restriction. Any address can call it. Because `last_reward_block` is a **global** (not per-staker) storage variable, only one successful call to `update_rewards` is permitted per block. An attacker who is a registered staker can front-run the sequencer every block, claiming rewards for themselves while blocking all other stakers from receiving rewards in those blocks.

### Finding Description

The spec at `docs/spec.md` line 1645 states:

> **Access control**: Only starkware sequencer.

However, the implementation at `src/staking/staking.cairo` lines 1449–1507 only calls `general_prerequisites()` (which checks for pause state and zero-address caller) and then validates staker existence and balance. There is no check that the caller is the sequencer. [1](#0-0) 

The critical global guard is `last_reward_block`: [2](#0-1) 

This single storage slot is written once per successful call: [3](#0-2) 

Because it is global, only **one** call to `update_rewards` can succeed per block. Any subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`.

The spec confirms this design: [4](#0-3) 

### Impact Explanation

**Attack A — Theft of unclaimed yield (High)**

An attacker who is a registered staker with effective balance calls `update_rewards(attacker_staker, disable_rewards: false)` in every block before the sequencer. Because `last_reward_block` is consumed, the sequencer's call for any other staker reverts. The attacker receives block rewards proportional to their stake for every block; all other stakers receive zero rewards for those blocks. Over time the attacker accumulates yield that rightfully belongs to other stakers.

**Attack B — Permanent freezing of unclaimed yield (High)**

An attacker who knows any valid active staker address (publicly readable via `get_stakers`) calls `update_rewards(any_staker, disable_rewards: true)` in every block. `last_reward_block` is consumed but no rewards are distributed to anyone. All stakers are permanently denied their yield for as long as the attacker continues. [5](#0-4) 

### Likelihood Explanation

- The function is publicly callable with no role gate.
- The attacker only needs to know one valid active staker address, which is publicly available via `get_stakers`.
- Front-running the sequencer on Starknet is feasible because the attacker can submit a transaction in the same block before the sequencer's system transaction is included.
- No special privileges, leaked keys, or external dependencies are required.

### Recommendation

Add an explicit sequencer-address check at the top of `update_rewards`, analogous to how `update_rewards_from_attestation_contract` checks for the attestation contract: [6](#0-5) 

Store the authorized sequencer address in contract storage (set during initialization or via a config function restricted to governance), and assert `get_caller_address() == self.sequencer_address.read()` as the first check inside `update_rewards`.

### Proof of Concept

1. Attacker registers as a staker via `stake(...)` with the minimum stake amount and waits K epochs for their balance to become effective.
2. In every subsequent block, attacker submits a transaction calling `staking.update_rewards(attacker_address, disable_rewards: false)`.
3. Because there is no caller check, the call succeeds, writes `last_reward_block = current_block`, and distributes block rewards to the attacker's `unclaimed_rewards_own`.
4. The sequencer's own `update_rewards` call for any other staker in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. After N blocks, the attacker has accumulated N × (attacker_share × block_rewards) in unclaimed rewards, while all other stakers have accumulated zero rewards for those N blocks.
6. Attacker calls `claim_rewards(attacker_address)` to withdraw the stolen yield. [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L1380-1395)
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
```

**File:** src/staking/staking.cairo (L1449-1507)
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
```

**File:** docs/spec.md (L1626-1652)
```markdown
### update_rewards
```rust
fn update_rewards(ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool);
```
#### description <!-- omit from toc -->
Calculate and update the current block rewards for the for the given `staker_address`.
Send pool rewards to the pools.
Distribute rewards only if `disable_rewards` is False and consensus rewards already started.
#### emits <!-- omit from toc -->
1. [Staker Rewards Updated](#staker-rewards-updated)
2. [Rewards Supplied To Delegation Pool](#rewards-supplied-to-delegation-pool)
#### errors <!-- omit from toc -->
1. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
2. [REWARDS\_ALREADY\_UPDATED](#rewards_already_updated)
3. [STAKER\_NOT\_EXISTS](#staker_not_exists)
4. [INVALID\_STAKER](#invalid_staker)
#### pre-condition <!-- omit from toc -->
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
1. Calculate total block rewards.
2. Calculate staker rewards (include commission) and pool rewards.
3. Update `unclaimed_rewards_own` of the staker.
4. Update and transfer rewards to the pools, if exist.
5. Update Reward Supplier's `unclaimed_rewards`.
6. Update `last_reward_block` to the current block.
```
