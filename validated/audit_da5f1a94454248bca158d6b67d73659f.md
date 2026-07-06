### Title
Unprivileged Caller Can Permanently Freeze Block Rewards by Calling `update_rewards` with `disable_rewards: true` - (File: src/staking/staking.cairo)

### Summary
`update_rewards` in `src/staking/staking.cairo` is a public function with no access control. Any unprivileged caller can invoke it with `disable_rewards: true` and a valid staker address, consuming the per-block reward slot (by writing `last_reward_block`) without distributing any rewards. Because the function enforces a strict one-call-per-block invariant, a subsequent legitimate call in the same block reverts with `REWARDS_ALREADY_UPDATED`. An attacker who front-runs every block permanently destroys that block's rewards for all stakers.

### Finding Description
`IStakingRewardsManager::update_rewards` is exposed as a public ABI entry point:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();          // only checks: not paused, caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    // Update last block rewards.
    self.last_reward_block.write(current_block_number);   // <-- global slot consumed

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // <-- exits without distributing
    }
    ...
}
``` [1](#0-0) 

`general_prerequisites` only asserts the contract is not paused and the caller is non-zero: [2](#0-1) 

There is no check that the caller is the staker, the staker's operational address, the attestation contract, or any other privileged role. The `last_reward_block` storage variable is **global** — it is shared across all stakers: [3](#0-2) 

The one-call-per-block invariant is enforced by: [4](#0-3) 

Once the attacker's call writes `last_reward_block = current_block_number`, every subsequent call in the same block reverts. The rewards for that block are permanently lost — there is no mechanism to retroactively distribute them.

### Impact Explanation
**High — Permanent freezing of unclaimed yield.**

An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` at the start of each block:
1. Consumes the block's reward slot without distributing rewards.
2. Causes all legitimate `update_rewards` calls in that block to revert with `REWARDS_ALREADY_UPDATED`.
3. Permanently destroys the block rewards for every staker and every delegation pool for that block.

Because block rewards are calculated per-block and never retroactively applied, the lost yield is irrecoverable. Sustained over many blocks, this constitutes a permanent, protocol-wide freeze of unclaimed yield.

### Likelihood Explanation
**Medium.** The attacker needs to submit one transaction per block, which is cheap on Starknet. The only requirement is knowing any valid, active staker address (trivially obtained from on-chain events such as `NewStaker`). No privileged access, no token balance, and no special setup is required. The attack can be automated and run indefinitely.

### Recommendation
Restrict who may call `update_rewards`. The function is intended to be called by the consensus layer (e.g., the block proposer or a designated sequencer role). Add an access-control check analogous to `assert_caller_is_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
    self.assert_caller_is_authorized_rewards_updater(); // NEW: restrict to trusted caller
    ...
}
```

Alternatively, remove the `disable_rewards` parameter from the public interface entirely and handle the "disable" case through a separate privileged admin function, so the public path always distributes rewards when called.

### Proof of Concept
1. Deploy the staking system and let staker `S` stake STRK.
2. Wait until consensus rewards are active (`is_pre_consensus()` returns `false`).
3. At the start of block `B`, attacker `A` (any non-zero address) calls:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. `last_reward_block` is written to `B`; the function returns early — no rewards distributed.
5. Staker `S` (or anyone else) calls `update_rewards(S, false)` in the same block → reverts with `REWARDS_ALREADY_UPDATED`.
6. Block `B`'s rewards are permanently lost.
7. Attacker repeats step 3 every block. All stakers and pool members receive zero block rewards indefinitely. [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
