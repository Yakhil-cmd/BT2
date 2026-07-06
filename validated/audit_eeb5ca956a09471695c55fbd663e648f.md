### Title
Unrestricted `update_rewards` with Caller-Controlled `disable_rewards` Enables Indefinite Suppression of All Staker Rewards - (File: src/staking/staking.cairo)

### Summary
`StakingRewardsManagerImpl::update_rewards` is callable by any unprivileged address and accepts a caller-supplied `disable_rewards: bool` parameter. When set to `true`, the function advances the global `last_reward_block` checkpoint without distributing any rewards, blocking every other staker from receiving consensus rewards for that block. An attacker can repeat this every block at low cost to indefinitely freeze all stakers' unclaimed yield.

### Finding Description
`update_rewards` is exposed as a public ABI entry point via `#[abi(embed_v0)]` on `StakingRewardsManagerImpl`. Its only gate is `general_prerequisites()`, which checks only that the contract is unpaused and the caller is non-zero. [1](#0-0) 

The function writes the current block number to the **global** `last_reward_block` storage slot before checking `disable_rewards`: [2](#0-1) 

When `disable_rewards` is `true`, execution returns immediately after that write, distributing nothing: [3](#0-2) 

Because `last_reward_block` is a single contract-wide value, any subsequent call to `update_rewards` in the same block fails with `REWARDS_ALREADY_UPDATED`: [4](#0-3) 

The storage declaration confirms it is a single scalar, not a per-staker map: [5](#0-4) 

The attacker only needs to supply any currently-active staker address with non-zero balance to pass the validity checks: [6](#0-5) 

The analog to the external report is direct: the interface declares `update_rewards` as a public function with a `disable_rewards` parameter, but the implementation contains no check enforcing that only a trusted caller may set that flag to `true`. Just as the Stylus `#[interface_id]` macro consumed `#[selector]` attributes without verifying that implementations matched, `update_rewards` accepts a reward-suppression flag without verifying the caller is authorised to suppress rewards.

### Impact Explanation
Every block in which the attacker fires the call, zero rewards are credited to any staker. Because the attack requires only one transaction per block and Starknet gas costs are low, an attacker can sustain this indefinitely. All stakers' consensus-era unclaimed yield is frozen for the duration of the attack. This matches **High: Permanent/Temporary freezing of unclaimed yield**.

### Likelihood Explanation
The entry point is fully public; no role, key, or privileged access is required. The attacker needs only a valid, active staker address (readable from on-chain events such as `NewStaker`) and enough STRK for gas. The attack is trivially scriptable and economically rational for any party wishing to harm the protocol or its stakers.

### Recommendation
Restrict `update_rewards` so that only a designated trusted caller (e.g., the sequencer, the attestation contract, or the staker themselves) may invoke it with `disable_rewards: true`. At minimum, add an access-control assertion analogous to `assert_caller_is_attestation_contract` used in `update_rewards_from_attestation_contract`: [7](#0-6) 

Alternatively, remove `disable_rewards` from the public ABI entirely and derive the flag internally from protocol state.

### Proof of Concept
```
// Attacker script (pseudocode, repeated every block)
loop {
    staking.update_rewards(
        staker_address = <any active staker>,
        disable_rewards = true,
    );
    // last_reward_block is now set to current block.
    // No rewards distributed.
    // All other update_rewards calls this block revert with REWARDS_ALREADY_UPDATED.
    wait_for_next_block();
}
```

1. Attacker calls `update_rewards(valid_staker, disable_rewards: true)` in block N.
2. `last_reward_block` is written to N; no rewards are distributed.
3. Any legitimate call to `update_rewards` in block N reverts (`REWARDS_ALREADY_UPDATED`).
4. Attacker repeats in block N+1, N+2, … indefinitely.
5. All stakers accumulate zero consensus rewards for the duration of the attack.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1398-1401)
```text
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

**File:** src/staking/staking.cairo (L1448-1460)
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
```

**File:** src/staking/staking.cairo (L1466-1483)
```text
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

```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```
