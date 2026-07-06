### Title
Unprivileged Caller Can Permanently Skip Block Rewards via Unguarded `disable_rewards` Parameter in `update_rewards` - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in `StakingRewardsManagerImpl` accepts a caller-controlled `disable_rewards: bool` parameter with no access-control check. Because `last_reward_block` is written to storage **before** the `disable_rewards` guard, any unprivileged address can call `update_rewards(valid_staker, disable_rewards: true)` to permanently consume the per-block reward slot without distributing any rewards, denying that block's yield to every staker and delegator in the protocol.

### Finding Description
`update_rewards` is the V3 consensus-phase reward distribution entry point. Its implementation at `src/staking/staking.cairo` lines 1449–1500 is:

```rust
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
    // ... staker existence / active / non-zero balance checks ...

    // ← last_reward_block is committed HERE, before the disable_rewards branch
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← exits with no rewards paid
    }
    // ... reward calculation and distribution ...
}
```

There is no `assert!(get_caller_address() == <trusted_role>, ...)` guard anywhere in the function. The `general_prerequisites()` call only enforces the pause flag. Consequently:

1. Any address can call `update_rewards(any_active_staker, disable_rewards: true)`.
2. `last_reward_block` is set to the current block number.
3. The function returns immediately, distributing zero rewards.
4. Every subsequent call in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. The rewards that would have accrued for that block are permanently lost for all stakers and delegators.

The analog to the reported Solana bug is exact: just as the restaking code failed to verify the caller owned the `vault_params` before setting the service, `update_rewards` fails to verify the caller is a privileged actor before consuming the per-block reward slot with `disable_rewards: true`.

### Impact Explanation
Every block that is "consumed" with `disable_rewards: true` results in zero STRK rewards being minted and distributed to stakers and their delegation pools for that block. Because `last_reward_block` is a single global variable shared across all stakers, one call poisons the entire block for the whole protocol. Repeated across many blocks, this constitutes permanent freezing of unclaimed yield / griefing of the reward pipeline with direct damage to all stakers and delegators.

This maps to the allowed impact: **"Permanent freezing of unclaimed yield or unclaimed royalties"** (High) or at minimum **"Griefing with no profit motive but damage to users or protocol"** (Medium).

### Likelihood Explanation
- The function is publicly callable with no role restriction.
- The only prerequisite is supplying any currently-active staker address, which is trivially discoverable from on-chain events (`NewStaker`).
- The attacker needs their transaction to land in the target block before the legitimate `update_rewards` call. On Starknet's sequencer model this requires either being the sequencer or submitting the transaction early in the block, which is a realistic condition for a motivated attacker.
- The attack is repeatable every block at negligible cost (gas only).

### Recommendation
Add an explicit caller check restricting `update_rewards` to a trusted role (e.g., the attestation contract, a governance-controlled rewards manager, or a dedicated role). For example:

```rust
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.rewards_manager_address.read(),
        "{}",
        Error::CALLER_IS_NOT_REWARDS_MANAGER,
    );
    // ...
}
```

Alternatively, remove the `disable_rewards` parameter from the public interface entirely and derive the skip condition solely from internal protocol state (`self.is_pre_consensus()`).

### Proof of Concept

1. Staker Alice is active with a non-zero STRK balance.
2. Attacker (any address) calls:
   ```
   IStakingRewardsManager(staking_contract).update_rewards(
       staker_address: alice_address,
       disable_rewards: true
   )
   ```
3. `last_reward_block` is set to the current block number; no rewards are distributed.
4. The legitimate sequencer/protocol call to `update_rewards` for the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. All stakers and delegators receive zero rewards for that block.
6. Attacker repeats step 2 every block, permanently suppressing all protocol rewards.

**Relevant code locations:** [1](#0-0) [2](#0-1)

### Citations

**File:** src/staking/staking.cairo (L1449-1490)
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
