### Title
Unprivileged Caller Can Permanently Block Consensus Reward Distribution via `update_rewards` - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the `Staking` contract has no access control and accepts a caller-controlled `disable_rewards` flag. Because a single global `last_reward_block` enforces a one-call-per-block invariant, any unprivileged attacker can front-run every legitimate reward-distribution call with `disable_rewards: true`, permanently preventing consensus rewards from accruing to all stakers and pool members.

### Finding Description
`update_rewards` is exposed as a public function with no role check:

```cairo
#[abi(embed_v0)]
impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
    fn update_rewards(
        ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
    ) {
        self.general_prerequisites();                          // only checks pause flag
        let current_block_number = starknet::get_block_number();
        assert!(
            current_block_number > self.last_reward_block.read(),
            "{}",
            Error::REWARDS_ALREADY_UPDATED,
        );
        ...
        self.last_reward_block.write(current_block_number);   // global write

        if disable_rewards || self.is_pre_consensus() {
            return;                                           // no rewards distributed
        }
        ...
    }
}
``` [1](#0-0) 

The storage field `last_reward_block` is a **single global value** shared across all stakers:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [2](#0-1) 

The function enforces that only one call per block succeeds (the `current_block_number > last_reward_block` assertion). Once `last_reward_block` is written to the current block number, every subsequent call in that block reverts with `REWARDS_ALREADY_UPDATED`.

An attacker exploits this as follows:

1. At the start of each block, call `update_rewards(any_active_staker, disable_rewards: true)`.
2. This passes all validity checks (staker exists, has non-zero balance, block is new), writes `last_reward_block = current_block`, and returns early without distributing any rewards.
3. Any legitimate call from the consensus layer in the same block reverts.
4. Repeating this every block permanently prevents all consensus rewards from being distributed.

The attacker only needs a valid, active `staker_address` as a parameter (trivially obtained from on-chain `NewStaker` events). No privileged role, no staked funds, and no special access are required.

### Impact Explanation
`last_reward_block` is global, so a single griefing call per block freezes reward accrual for **every staker and pool member** in the protocol. Stakers' `unclaimed_rewards_own` and pool members' cumulative reward traces never advance. This constitutes permanent freezing of unclaimed yield for all participants.

### Likelihood Explanation
The function is publicly callable with no access control. On Starknet, transaction fees are low, making it economically viable for an attacker to submit one transaction per block indefinitely. The attacker requires no capital at risk and gains no direct profit, making this a pure griefing vector. Any competitor, protocol adversary, or malicious actor has clear motive.

### Recommendation
Restrict `update_rewards` to a trusted caller — either the consensus/attestation contract or a designated operator role. For example:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.roles.only_reward_distributor(); // add a dedicated role
    ...
}
```

Alternatively, remove the `disable_rewards` parameter from the public interface and derive the flag internally from on-chain state (e.g., whether the staker is in an exit window), so callers cannot inject it.

### Proof of Concept

1. Deploy the staking contract and have one legitimate staker `S` with non-zero balance.
2. At block `N`, attacker calls:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
3. `last_reward_block` is set to `N`; no rewards are distributed.
4. The consensus layer's call to `update_rewards(S, false)` in block `N` reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeat at block `N+1`, `N+2`, … — all stakers permanently receive zero consensus rewards. [3](#0-2) [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1447-1500)
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
```
