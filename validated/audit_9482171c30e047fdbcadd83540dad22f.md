### Title
Unrestricted `disable_rewards` Flag in `update_rewards` Permanently Blocks Consensus Reward Distribution — (File: `src/staking/staking.cairo`)

---

### Summary

`update_rewards` is a public, permissionless function that accepts a caller-controlled `disable_rewards: bool` parameter. When `disable_rewards` is `true`, the function still writes the current block number to the global `last_reward_block` storage slot but returns before distributing any rewards. Because `last_reward_block` is a single global gate that prevents any staker from receiving rewards for the same block, an unprivileged attacker can call `update_rewards(any_valid_staker, disable_rewards: true)` once per block to permanently drain every block's consensus rewards from all stakers.

---

### Finding Description

`update_rewards` is embedded as a public ABI entry point with no role check beyond `general_prerequisites()` (not paused, non-zero caller):

```cairo
#[abi(embed_v0)]
impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
    fn update_rewards(
        ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
    ) {
        self.general_prerequisites();                          // only: not paused, caller != 0
        let current_block_number = starknet::get_block_number();
        assert!(
            current_block_number > self.last_reward_block.read(),
            "{}",
            Error::REWARDS_ALREADY_UPDATED,
        );
        ...
        assert!(staker_total_strk_balance.is_non_zero(), "{}", Error::INVALID_STAKER);

        // ← global gate is written HERE, before the early-return check
        self.last_reward_block.write(current_block_number);

        if disable_rewards || self.is_pre_consensus() {
            return;                                            // ← no rewards distributed
        }
        ...
    }
}
``` [1](#0-0) 

The critical ordering is:

1. `last_reward_block` is updated to `current_block_number` (line 1485).
2. Only *after* that write does the function check `disable_rewards` and return early (line 1487).

`last_reward_block` is a **single global** storage slot:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [2](#0-1) 

Any subsequent call to `update_rewards` in the same block will fail the assertion `current_block_number > last_reward_block`, so the block's rewards are irrecoverably lost.

The attacker only needs to supply any currently-active staker address with a non-zero STRK balance — information that is fully public on-chain.

---

### Impact Explanation

Every block in the consensus-rewards phase carries a STRK (and potentially BTC) block reward computed by `calculate_block_rewards` and distributed to stakers and their delegation pools via `_update_rewards`. By calling `update_rewards(valid_staker, true)` once per block, an attacker permanently prevents that block's rewards from ever being distributed to any staker or pool. Repeated across every block, this freezes the entire consensus reward stream indefinitely.

This matches the allowed impact: **High — Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

- The function is a public ABI entry point with no privileged-role guard.
- The attacker needs only a valid staker address (publicly readable from on-chain events) and enough gas to submit one transaction per block.
- There is no economic cost beyond gas; the attacker need not hold any stake.
- The attack is fully permissionless and repeatable every block.

---

### Recommendation

Restrict who may call `update_rewards` with `disable_rewards: true`, or restructure the function so that `last_reward_block` is only written when rewards are actually distributed. For example:

- Move `self.last_reward_block.write(current_block_number)` to *after* the `disable_rewards` / `is_pre_consensus` guard, so the global gate is only advanced when rewards are genuinely processed.
- Or add an access-control check (e.g., `only_consensus_contract`) before accepting `disable_rewards: true`.

---

### Proof of Concept

```
Attacker (any EOA)
  │
  ├─ every block N:
  │    call Staking.update_rewards(
  │        staker_address = <any active staker>,
  │        disable_rewards = true
  │    )
  │
  │    Inside update_rewards:
  │      assert(block_N > last_reward_block)  ✓  (first call this block)
  │      ... staker validity checks pass ...
  │      last_reward_block ← block_N          ← global gate advanced
  │      if disable_rewards { return; }       ← no rewards distributed
  │
  └─ All legitimate calls to update_rewards for block N now revert:
       assert(block_N > last_reward_block)  ✗  (last_reward_block == block_N)
       → block N's rewards are permanently lost for every staker and pool
``` [3](#0-2)

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
