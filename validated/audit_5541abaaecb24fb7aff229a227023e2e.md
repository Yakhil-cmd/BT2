### Title
Unprivileged Caller Can Permanently Grief Consensus Reward Distribution via `update_rewards` - (File: `src/staking/staking.cairo`)

### Summary

The `update_rewards` function in `Staking.cairo` is callable by any unprivileged address. It writes to the global `last_reward_block` storage slot before distributing rewards, and the function enforces a one-call-per-block invariant. An attacker can front-run every legitimate consensus-layer call with `disable_rewards: true`, consuming the per-block slot without distributing any rewards, thereby permanently starving all stakers of consensus-epoch yield.

### Finding Description

`update_rewards` is exposed as a public function under `IStakingRewardsManager`. Its only access guard is `general_prerequisites()`, which checks that the contract is not paused and the caller is non-zero — no role or identity check is performed. [1](#0-0) 

Inside the function, the very first state-mutating step is to write the current block number into the global `last_reward_block` field: [2](#0-1) 

The guard that enforces the one-call-per-block invariant is checked **before** any reward calculation:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [3](#0-2) 

`last_reward_block` is a single global field shared across all stakers: [4](#0-3) 

The caller-controlled `disable_rewards` boolean is accepted without validation:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [5](#0-4) 

**Attack path:**

1. In every block N, the attacker calls `update_rewards(any_valid_staker, disable_rewards: true)`.
2. `last_reward_block` is set to N; the function returns immediately without distributing rewards.
3. Any subsequent legitimate call to `update_rewards` in block N reverts with `REWARDS_ALREADY_UPDATED`.
4. All stakers receive zero consensus rewards for block N.
5. The attacker repeats in block N+1, N+2, … indefinitely.

A valid `staker_address` is required, but all staker addresses are public on-chain. The attacker needs no stake, no special role, and no funds beyond gas.

### Impact Explanation

All stakers are permanently denied consensus-epoch block rewards for as long as the attack is sustained. `last_reward_block` is global, so a single attacker transaction per block freezes yield for the entire staker set. This constitutes **temporary (indefinitely sustainable) freezing of unclaimed yield** for all stakers and their delegators.

### Likelihood Explanation

- Entry point is fully public; no role, no stake, no approval required.
- The attacker only needs to know one live staker address (trivially obtained from on-chain events).
- On Starknet, transaction fees are low, making sustained per-block griefing economically viable.
- The attack is silent — it does not revert; it simply consumes the per-block slot.

### Recommendation

Restrict `update_rewards` to a trusted caller (e.g., the attestation contract, a designated consensus relayer, or a specific role). Alternatively, make `last_reward_block` per-staker rather than global, so one call cannot block all others. At minimum, remove the caller-controlled `disable_rewards` parameter from the public interface and derive it internally.

```cairo
// Option A: role-gate the function
fn update_rewards(ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool) {
    self.roles.only_rewards_manager(); // add a dedicated role
    ...
}

// Option B: per-staker last_reward_block
last_reward_block: Map<ContractAddress, BlockNumber>,
```

### Proof of Concept

```
Block N:
  Attacker tx:  update_rewards(staker=<any_valid_staker>, disable_rewards=true)
    → last_reward_block := N
    → returns early, zero rewards distributed

  Legitimate consensus tx: update_rewards(staker=<target_staker>, disable_rewards=false)
    → assert!(N > N)  ← FAILS with REWARDS_ALREADY_UPDATED
    → staker receives 0 rewards for block N

Repeat every block → all stakers receive 0 consensus rewards indefinitely.
``` [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1448-1507)
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
