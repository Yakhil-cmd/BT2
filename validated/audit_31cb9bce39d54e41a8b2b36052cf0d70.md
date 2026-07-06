### Title
Missing Caller Check on `update_rewards` Allows Any Address to Permanently Freeze Per-Block Yield - (File: `src/staking/staking.cairo`)

---

### Summary

`IStakingRewardsManager::update_rewards` is specified to be callable only by the Starkware sequencer, but the implementation contains no caller check. Any unprivileged address can call it with `disable_rewards: true`, consuming the global `last_reward_block` slot for the current block without distributing any rewards. Because the contract enforces a strict one-call-per-block invariant, the sequencer is permanently locked out from distributing rewards for that block.

---

### Finding Description

The protocol specification explicitly restricts `update_rewards` to the Starkware sequencer:

> **access control**: Only starkware sequencer. [1](#0-0) 

The implementation in `StakingRewardsManagerImpl` performs no such check. The function body begins with `self.general_prerequisites()` (a pause check), then immediately validates the block number against `last_reward_block`, validates the staker, and writes the current block number to `last_reward_block` — all without ever inspecting `get_caller_address()`: [2](#0-1) 

The critical write that consumes the block slot happens unconditionally before the `disable_rewards` guard: [3](#0-2) 

After `last_reward_block` is written, the early-return path (`disable_rewards || self.is_pre_consensus()`) exits without distributing any rewards. The sequencer's subsequent call for the same block will revert with `REWARDS_ALREADY_UPDATED` because the block-number guard `current_block_number > self.last_reward_block.read()` is now false.

There is no `only_sequencer`, `assert_caller_is_sequencer`, or any equivalent function anywhere in the production Cairo source — the guard is entirely absent. [4](#0-3) 

The interface definition confirms the function is public with no documented caller restriction in code: [5](#0-4) 

---

### Impact Explanation

`last_reward_block` is a single global storage slot. One successful attacker call per block permanently discards that block's entire reward distribution for the targeted staker (and their pool). Because the block cannot be revisited, the yield is frozen forever — it is never credited to `unclaimed_rewards_own` or transferred to the pool contract. This matches the allowed High impact: **Permanent freezing of unclaimed yield**. [6](#0-5) 

---

### Likelihood Explanation

The entry point is a public external function on a deployed contract. The attacker needs only:
1. Any valid, active staker address (all staker addresses are observable on-chain via `NewStaker` events).
2. To call `update_rewards(staker_address, disable_rewards: true)` once per block before the sequencer does.

No privileged role, leaked key, or external dependency is required. The attack is cheap (a single transaction per block) and can be sustained indefinitely to suppress all consensus-era block rewards for one or more stakers.

---

### Recommendation

Add a sequencer-only guard at the top of `update_rewards`, analogous to the attestation-contract guard already present in `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    assert!(
        starknet::get_caller_address() == starknet::get_sequencer_address(),
        "{}",
        Error::CALLER_IS_NOT_SEQUENCER,
    );
    // ... rest of function
}
``` [7](#0-6) 

---

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. A valid staker `S` exists with non-zero balance at the current epoch.
3. Attacker (any EOA) calls `update_rewards(S, disable_rewards: true)` at block `B`.
4. The function passes all checks, writes `last_reward_block = B`, and returns early — zero rewards distributed.
5. The sequencer attempts `update_rewards(S, disable_rewards: false)` at block `B` — reverts with `REWARDS_ALREADY_UPDATED`.
6. Block `B`'s rewards for staker `S` and their pool are permanently lost.

Repeating step 3 every block continuously suppresses all yield for `S`.

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/staking.cairo (L1392-1401)
```text
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
```

**File:** src/staking/staking.cairo (L1447-1508)
```text
    #[abi(embed_v0)]
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
