### Title
Pool Members Can Claim Rewards Through `Pool` Contract When Staking Is Paused - (File: `src/pool/pool.cairo`)

### Summary

The `Staking` contract has a pause mechanism enforced via `general_prerequisites()` → `assert_is_unpaused()`. All state-changing functions in `Staking` call `general_prerequisites()`, including `Staking::claim_rewards`. However, the `Pool` contract's `claim_rewards` function performs no pause check and makes no call back to the `Staking` contract, allowing pool members to claim accumulated yield even when the protocol is paused.

### Finding Description

The `Staking` contract enforces a pause guard through `assert_is_unpaused`: [1](#0-0) 

This guard is invoked by `general_prerequisites()`, which is called at the top of every state-changing function in `Staking`, including `claim_rewards`: [2](#0-1) 

When paused, stakers cannot call `Staking::claim_rewards` — it reverts immediately.

However, `Pool::claim_rewards` contains no pause check and no call to the `Staking` contract. It reads accumulated rewards from internal pool state and transfers STRK directly to the reward address: [3](#0-2) 

The reward tokens are already held in the pool contract (deposited via `update_rewards_from_staking_contract`), so the transfer succeeds regardless of the `Staking` contract's pause state.

### Impact Explanation

When governance pauses the protocol — for example, due to a discovered bug in reward accounting — the intent is to freeze all reward flows. Stakers are correctly blocked from claiming via `Staking::claim_rewards`. But pool members can still drain their accumulated (potentially incorrectly calculated) rewards through `Pool::claim_rewards`. This constitutes **theft of unclaimed yield** during a pause window, matching the allowed impact: **High: Theft of unclaimed yield or unclaimed royalties**.

### Likelihood Explanation

Any pool member can call `Pool::claim_rewards` at any time. The pool contract is a separate deployed contract with no reference to the staking pause flag. No special privilege is required. The attacker-controlled entry path is direct: call `Pool::claim_rewards(pool_member)` while `Staking::is_paused == true`.

### Recommendation

Add a pause check to `Pool::claim_rewards` (and other pool functions that move funds, such as `exit_delegation_pool_intent` when the staker is removed). The pool contract already holds a reference to the staking contract via `staking_pool_dispatcher`. A helper can query the pause state:

```cairo
fn assert_staking_not_paused(self: @ContractState) {
    let staking_dispatcher = IStakingDispatcher {
        contract_address: self.staking_pool_dispatcher.contract_address.read(),
    };
    assert!(!staking_dispatcher.is_paused(), "{}", Error::CONTRACT_IS_PAUSED);
}
```

Apply this check at the top of `Pool::claim_rewards`, `Pool::exit_delegation_pool_intent`, and `Pool::exit_delegation_pool_action`.

### Proof of Concept

```
1. Staker registers and opens a delegation pool.
2. Pool member calls `Pool::enter_delegation_pool(reward_address, amount)`.
3. Several epochs pass; rewards accumulate in the pool via `update_rewards_from_staking_contract`.
4. Security agent calls `Staking::pause()` → `is_paused` becomes `true`.
5. Staker attempts `Staking::claim_rewards(staker_address)` → reverts with CONTRACT_IS_PAUSED.
6. Pool member calls `Pool::claim_rewards(pool_member)` → succeeds, STRK transferred to reward_address.
7. Pool member has claimed yield that should have been frozen by the pause.
```

The root cause is that `Pool::claim_rewards` at [4](#0-3)  never queries `IStakingDispatcher::is_paused()`, while the analogous `Staking::claim_rewards` at [2](#0-1)  is gated behind `general_prerequisites()` which calls `assert_is_unpaused` at [1](#0-0) .

### Citations

**File:** src/staking/staking.cairo (L411-414)
```text
        fn claim_rewards(ref self: ContractState, staker_address: ContractAddress) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

**File:** src/staking/staking.cairo (L1657-1659)
```text
        fn assert_is_unpaused(self: @ContractState) {
            assert!(!self.is_paused(), "{}", Error::CONTRACT_IS_PAUSED);
        }
```

**File:** src/pool/pool.cairo (L335-377)
```text
        fn claim_rewards(ref self: ContractState, pool_member: ContractAddress) -> Amount {
            // Asserts.
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let caller_address = get_caller_address();
            let reward_address = pool_member_info.reward_address;
            assert!(
                caller_address == pool_member || caller_address == reward_address,
                "{}",
                Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );

            let until_checkpoint = self.get_current_checkpoint(:pool_member);

            // Calculate rewards and update entry_to_claim_from.
            let (mut rewards, updated_entry_to_claim_from) = self
                .calculate_rewards(
                    :pool_member,
                    from_checkpoint: pool_member_info.reward_checkpoint,
                    :until_checkpoint,
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
            rewards += pool_member_info._unclaimed_rewards_from_v0;
            pool_member_info._unclaimed_rewards_from_v0 = Zero::zero();
            pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
            pool_member_info.reward_checkpoint = until_checkpoint;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());

            // Emit event.
            self
                .emit(
                    Events::PoolMemberRewardClaimed {
                        pool_member, reward_address, amount: rewards,
                    },
                );

            rewards
        }
```
