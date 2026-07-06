### Title
Griefing DOS via `update_rewards(disable_rewards: true)` Advances Global `last_reward_block` Without Distributing Rewards - (File: `src/staking/staking.cairo`)

### Summary
The public `update_rewards` function in `staking.cairo` accepts an unguarded `disable_rewards: bool` parameter. When any unprivileged caller invokes it with `disable_rewards: true`, the function advances the global `last_reward_block` storage variable to the current block number and returns early — without distributing any block rewards. Because `last_reward_block` is a single global checkpoint, every subsequent legitimate `update_rewards` call in the same block reverts with `REWARDS_ALREADY_UPDATED`. This is a direct analog to the ERC20 permit front-running DOS: in both cases an attacker exploits a publicly callable state-advancing operation to invalidate a legitimate, reward-bearing call.

### Finding Description

`update_rewards` is declared in `StakingRewardsManagerImpl` with no caller restriction:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
``` [1](#0-0) 

The function first asserts the current block is strictly greater than the stored `last_reward_block`:

```cairo
assert!(
    current_block_number > self.last_reward_block.read(),
    "{}",
    Error::REWARDS_ALREADY_UPDATED,
);
``` [2](#0-1) 

It then unconditionally writes the current block number to `last_reward_block`:

```cairo
self.last_reward_block.write(current_block_number);
``` [3](#0-2) 

And immediately returns if `disable_rewards` is `true`, skipping all reward computation and distribution:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
``` [4](#0-3) 

`last_reward_block` is a single global storage slot shared across all stakers:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [5](#0-4) 

**Attack path:**
1. In block N, an attacker calls `update_rewards(any_valid_staker_address, disable_rewards: true)`.
2. The function passes all staker-existence checks, writes `last_reward_block = N`, and returns without distributing rewards.
3. Every legitimate `update_rewards` call in block N now fails with `REWARDS_ALREADY_UPDATED` because `current_block_number (N) > last_reward_block (N)` is `false`.
4. All stakers lose their block rewards for block N.
5. The attacker repeats this every block to permanently freeze all block reward accrual.

The attacker only needs to supply any currently-active staker address (publicly readable from events or the `stakers` vector) and pay the gas cost of one transaction per block.

### Impact Explanation

Block rewards are the primary yield mechanism for stakers in the consensus-rewards phase. By advancing `last_reward_block` without distributing rewards, the attacker causes **permanent freezing of unclaimed yield** for all stakers across the entire protocol. Because the attack requires only one cheap transaction per block and the `last_reward_block` is global, a single attacker can suppress rewards for every staker simultaneously at minimal cost.

This matches the allowed impact: **Permanent freezing of unclaimed yield / Temporary freezing of funds**.

### Likelihood Explanation

- `update_rewards` is a fully public, permissionless function — no role check, no caller whitelist.
- The `disable_rewards` parameter carries no access control.
- Any valid staker address (trivially obtained from on-chain events) satisfies the only precondition.
- The economic cost is one Starknet transaction per block; the attacker gains nothing but inflicts protocol-wide reward denial.

### Recommendation

Restrict who may pass `disable_rewards: true`. The simplest fix is to require that the caller is either the staker themselves, their operational address, or a privileged role (e.g., `security_agent`) before honouring `disable_rewards: true`. Alternatively, remove the `disable_rewards` parameter from the public interface entirely and handle the "skip rewards" case through a separate access-controlled function.

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
+   if disable_rewards {
+       self.roles.only_security_agent(); // or assert caller == staker / operational
+   }
    ...
```

### Proof of Concept

1. Staker Alice is active and expects block rewards in block N.
2. Attacker Bob calls `staking.update_rewards(alice_address, disable_rewards: true)` in block N.
3. `last_reward_block` is set to N; no rewards are distributed.
4. Alice (or the sequencer on her behalf) calls `staking.update_rewards(alice_address, disable_rewards: false)` in the same block N.
5. The call reverts: `REWARDS_ALREADY_UPDATED` because `N > N` is false.
6. Alice receives zero block rewards for block N.
7. Bob repeats step 2 every block; Alice (and all other stakers) accrue zero rewards indefinitely. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1449-1489)
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
