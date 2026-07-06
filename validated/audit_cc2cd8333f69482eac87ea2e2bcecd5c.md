### Title
Missing Access Control on `update_rewards` Allows Anyone to Permanently Freeze Staker Yield - (File: `src/staking/staking.cairo`)

### Summary
The `update_rewards` function in `StakingRewardsManagerImpl` is publicly callable by any address. The protocol specification explicitly requires this function to be restricted to "Only starkware sequencer," but no such check exists in the implementation. An unprivileged attacker can call `update_rewards(..., disable_rewards: true)` for any staker every block, permanently consuming the per-block reward slot without distributing any rewards, causing all stakers to permanently lose their unclaimed yield.

### Finding Description
The spec at `docs/spec.md` line 1644–1645 states:

> **access control**: Only starkware sequencer.

The implementation at `src/staking/staking.cairo` lines 1447–1507 contains no caller check of any kind. A grep for `CALLER_IS_NOT_SEQUENCER`, `only_sequencer`, `sequencer_address`, or `get_sequencer` across all of `src/` returns zero matches.

The function's only guard is a per-block deduplication check:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
```

After this check passes, the function unconditionally writes `last_reward_block` to the current block number:

```cairo
self.last_reward_block.write(current_block_number);
```

If `disable_rewards` is `true`, execution returns immediately after this write, distributing zero rewards. Because `last_reward_block` is now equal to the current block, any subsequent call — including the legitimate sequencer's call — will revert with `REWARDS_ALREADY_UPDATED`. The reward slot for that block is permanently consumed and the staker's yield for that block is irrecoverably lost.

### Impact Explanation
An attacker calling `update_rewards(any_active_staker, disable_rewards: true)` once per block:
- Permanently prevents the sequencer from distributing rewards for that block to the targeted staker and their delegation pools.
- Causes permanent, irreversible loss of unclaimed yield for every staker targeted.
- Requires no funds, no special role, and no precondition beyond the staker being active.

This maps to the allowed High impact: **Permanent freezing of unclaimed yield**.

### Likelihood Explanation
The function is part of the public ABI (`#[abi(embed_v0)]`), callable by any EOA or contract on Starknet. The only cost is a transaction fee. The attack can be automated to run every block against every active staker. There is no economic barrier and no on-chain defense.

### Recommendation
Add a caller check at the top of `update_rewards` that asserts `get_caller_address()` equals the expected Starknet sequencer address (or a stored, governance-controlled sequencer address), consistent with the access control specified in the protocol spec. A dedicated error constant `CALLER_IS_NOT_SEQUENCER` should be introduced, matching the pattern used for `CALLER_IS_NOT_ATTESTATION_CONTRACT` in `update_rewards_from_attestation_contract`.

### Proof of Concept

**Spec requirement** (access control is "Only starkware sequencer"): [1](#0-0) 

**Interface declaration** (public, no restriction noted): [2](#0-1) 

**Implementation — no caller check, unconditional `last_reward_block` write before the `disable_rewards` branch:** [3](#0-2) 

**Attack path:**
1. Attacker calls `update_rewards(victim_staker_address, disable_rewards: true)` at any new block.
2. The `REWARDS_ALREADY_UPDATED` guard passes (new block).
3. `last_reward_block` is written to the current block (line 1485).
4. Execution returns at line 1488 with zero rewards distributed.
5. The sequencer's subsequent call for the same block reverts with `REWARDS_ALREADY_UPDATED`.
6. The staker's yield for that block is permanently lost.
7. Repeat every block to permanently freeze all yield for any staker.

**Contrast with the correctly guarded sibling function** `update_rewards_from_attestation_contract`, which does enforce caller identity: [4](#0-3)

### Citations

**File:** docs/spec.md (L1157-1158)
```markdown
#### access control <!-- omit from toc -->
Only attestation contract.
```

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
```

**File:** src/staking/interface.cairo (L304-311)
```text
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```

**File:** src/staking/staking.cairo (L1447-1489)
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
```
