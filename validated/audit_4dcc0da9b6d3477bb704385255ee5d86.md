### Title
Missing Caller Authorization in `update_rewards` Allows Any Address to Block Consensus Reward Distribution - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in `staking.cairo` contains no caller authorization check, despite the protocol specification explicitly restricting it to "Only starkware sequencer." Any unprivileged address can call it with `disable_rewards: true`, which writes the current block number into the global `last_reward_block` storage variable and returns early without distributing rewards. This permanently consumes the per-block reward slot, preventing the sequencer from distributing consensus rewards for that block.

### Finding Description
`IStakingRewardsManager::update_rewards` is the consensus-phase (V3) reward distribution entry point. The spec at `docs/spec.md` line 1645 states its access control is "Only starkware sequencer." The implementation, however, performs no such check:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks pause
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker existence / activity checks ...
    self.last_reward_block.write(current_block_number);   // ← written unconditionally
    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← exits without distributing
    }
    // ... reward distribution ...
```

`last_reward_block` is a single global `StoragePointer` (not a per-staker map). Writing it with `disable_rewards: true` consumes the entire block's reward slot for all stakers. Any subsequent call in the same block — including the sequencer's legitimate call — hits `REWARDS_ALREADY_UPDATED`.

The attacker only needs to supply any valid, active staker address (all staker addresses are publicly readable from contract events). No privileged role, no stake, no cost beyond gas.

### Impact Explanation
An unprivileged attacker calling `update_rewards(any_active_staker, disable_rewards: true)` in every block permanently prevents all stakers from accumulating consensus rewards. Because `last_reward_block` is global, a single call per block is sufficient to freeze yield for the entire protocol. This matches **High: Permanent freezing of unclaimed yield**.

### Likelihood Explanation
The entry point is public, requires only a valid staker address (trivially obtained from on-chain events), and costs only gas. There is no slashing, no bond, and no punishment. The attack is repeatable every block indefinitely.

### Recommendation
Add an explicit sequencer-address check at the top of `update_rewards`, analogous to the checks already present in `update_current_epoch_block_rewards` and `claim_rewards` in `reward_supplier.cairo`:

```cairo
assert!(
    get_caller_address() == self.sequencer_address.read(),
    "{}",
    Error::CALLER_IS_NOT_SEQUENCER,
);
```

Alternatively, store the authorized caller address during construction and enforce it in `update_rewards`.

### Proof of Concept

1. Deploy the full system (staking + attestation + reward supplier).
2. Register a staker and advance K epochs so the staker has an effective balance.
3. Enable consensus rewards (`set_consensus_rewards_first_epoch`).
4. From **any** address (no special role), call:
   ```cairo
   IStakingRewardsManagerDispatcher { contract_address: staking_contract }
       .update_rewards(staker_address: known_active_staker, disable_rewards: true);
   ```
5. Observe `last_reward_block` is now set to the current block.
6. The sequencer's legitimate call to `update_rewards(..., disable_rewards: false)` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
7. No rewards are distributed for this block; `unclaimed_rewards_own` of the staker is unchanged.
8. Repeating step 4 every block permanently freezes all staker and delegator yield.

**Root cause lines:** [1](#0-0) 

**Spec access-control requirement (violated):** [2](#0-1) 

**Contrast: `reward_supplier.cairo` correctly enforces caller identity:** [3](#0-2)

### Citations

**File:** src/staking/staking.cairo (L1448-1489)
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
```

**File:** docs/spec.md (L1643-1646)
```markdown
Rewards did not disttributed for the current block yet. 
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```

**File:** src/reward_supplier/reward_supplier.cairo (L166-172)
```text
        fn update_current_epoch_block_rewards(ref self: ContractState) -> (Amount, Amount) {
            let staking_contract = self.staking_contract.read();
            assert!(
                get_caller_address() == staking_contract,
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );
```
