### Title
Unprivileged Caller Can Invoke `update_rewards` With `disable_rewards: true` to Freeze All Staker Consensus Rewards — (File: `src/staking/staking.cairo`)

### Summary
The `update_rewards` function in the `Staking` contract is publicly callable with no access control beyond a pause check and non-zero caller check. It accepts a `disable_rewards: bool` parameter. When called with `disable_rewards: true`, the function unconditionally writes the current block number to the global `last_reward_block` storage variable **before** checking `disable_rewards`, then returns without distributing any rewards. Because only one call per block is permitted (enforced by the `last_reward_block` guard), any attacker can consume the reward slot for every block, permanently preventing all stakers from receiving consensus rewards.

### Finding Description
`update_rewards` is exposed as a public ABI function via `IStakingRewardsManager`:

```cairo
#[abi(embed_v0)]
impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
    fn update_rewards(
        ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
    ) {
        self.general_prerequisites();                          // only checks pause + non-zero caller
        let current_block_number = starknet::get_block_number();
        assert!(
            current_block_number > self.last_reward_block.read(),
            "{}",
            Error::REWARDS_ALREADY_UPDATED,
        );
        ...
        // Update last block rewards.          ← written unconditionally
        self.last_reward_block.write(current_block_number);

        if disable_rewards || self.is_pre_consensus() {
            return;                            ← exits with no rewards distributed
        }
        ...
    }
}
``` [1](#0-0) 

`last_reward_block` is a **single global** storage slot shared across all stakers: [2](#0-1) 

`general_prerequisites` imposes no caller identity restriction: [3](#0-2) 

The sequence is:

1. Attacker calls `update_rewards(any_valid_active_staker, disable_rewards: true)` in block N.
2. `last_reward_block` is set to N.
3. No rewards are distributed.
4. Every other call to `update_rewards` in block N — for any staker — reverts with `REWARDS_ALREADY_UPDATED`.
5. Attacker repeats in block N+1, N+2, …

The only precondition is that the attacker supplies a valid, active staker address with non-zero balance. Staker addresses are publicly observable from on-chain events (`NewStaker`).

### Impact Explanation
Because `last_reward_block` is global, a single attacker call per block silences consensus reward distribution for **all** stakers simultaneously. If the attacker sustains this across consecutive blocks, no staker ever accumulates `unclaimed_rewards_own` in the consensus-rewards regime. This constitutes **permanent freezing of unclaimed yield** for the entire protocol — a High-severity impact under the allowed scope.

### Likelihood Explanation
The function is fully public. The attacker needs only a valid staker address (trivially obtained from events) and enough gas to call once per block. On Starknet, per-transaction costs are low, making sustained griefing economically feasible. No privileged key, bridge access, or external dependency is required.

### Recommendation
Restrict who may supply `disable_rewards: true`. Options:

1. **Caller restriction**: Only allow the staker's own address or their registered operational address to call `update_rewards`. Add a check such as:
   ```cairo
   let caller = get_caller_address();
   assert!(
       caller == staker_address || caller == staker_info.operational_address,
       "{}",
       Error::UNAUTHORIZED_CALLER,
   );
   ```
2. **Deferred write**: Only update `last_reward_block` when rewards are actually distributed (move the write after the `disable_rewards` guard), so a no-op call does not consume the block slot.

### Proof of Concept

```
Block N:
  Attacker → update_rewards(alice_staker_address, disable_rewards=true)
    → last_reward_block := N
    → returns, no rewards distributed

  Alice → update_rewards(alice_staker_address, disable_rewards=false)
    → assert!(N > N)  ← FAILS: REWARDS_ALREADY_UPDATED

  Bob  → update_rewards(bob_staker_address, disable_rewards=false)
    → assert!(N > N)  ← FAILS: REWARDS_ALREADY_UPDATED

Block N+1:
  Attacker repeats → last_reward_block := N+1
  Alice and Bob again blocked.

Result: alice.unclaimed_rewards_own and bob.unclaimed_rewards_own never increase.
```

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1448-1490)
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
