Based on my investigation, I found a clear analog vulnerability. The spec mandates "Only starkware sequencer" access control for `update_rewards`, but the implementation has **no caller check whatsoever**.

---

### Title
Unrestricted `update_rewards` Allows Any Caller to Permanently Suppress Block Reward Distribution - (File: `src/staking/staking.cairo`)

### Summary

`IStakingRewardsManager::update_rewards` is callable by any address. An attacker can front-run the legitimate sequencer by calling it with `disable_rewards: true`, which marks the current block as "already updated" in `last_reward_block` without distributing any rewards. The sequencer's subsequent call for the same block reverts with `REWARDS_ALREADY_UPDATED`, permanently destroying that block's rewards for all stakers and delegators.

### Finding Description

The spec explicitly states the access control for `update_rewards` is **"Only starkware sequencer"**: [1](#0-0) 

However, the implementation in `StakingRewardsManagerImpl` performs no caller identity check. The only gate is `general_prerequisites()`, which only checks whether the contract is paused: [2](#0-1) 

The function unconditionally writes `current_block_number` into the global `last_reward_block` storage variable **before** the `disable_rewards` branch: [3](#0-2) 

Because the guard at line 1454 requires `current_block_number > last_reward_block`, once any caller writes the current block number there, **no further call to `update_rewards` can succeed for that block**, regardless of who calls it or what `disable_rewards` value they pass.

The interface definition confirms the function is publicly exposed with no role annotation: [4](#0-3) 

### Impact Explanation

An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` in block N:

1. Passes all validation (staker exists, is active, has non-zero balance).
2. Writes `N` into `last_reward_block`.
3. Returns early at the `disable_rewards` branch — **zero rewards distributed**.
4. The legitimate sequencer's call for block N reverts with `REWARDS_ALREADY_UPDATED`.
5. Block N's consensus rewards are **permanently lost** — there is no recovery path.

This maps to **Permanent freezing of unclaimed yield** (High severity). Repeated across many blocks, it constitutes a sustained denial of yield to all stakers and delegators.

### Likelihood Explanation

- The attacker needs only a valid `staker_address` (publicly readable from on-chain events) and enough gas to front-run one transaction per block.
- No tokens, no stake, no privileged role required.
- The attacker has no profit motive but zero cost beyond gas, making this a pure griefing attack.
- On Starknet L2, transaction ordering within a block is sequencer-controlled, but the function is callable by any L2 account, so a determined attacker can submit the call in every block.

### Recommendation

Add a caller check at the top of `update_rewards` that asserts `get_caller_address()` equals the registered Starkware sequencer address (or a dedicated role), consistent with the spec's stated access control. For example:

```rust
fn update_rewards(...) {
    self.general_prerequisites();
    assert!(
        get_caller_address() == self.sequencer_address.read(),
        "{}",
        Error::ONLY_SEQUENCER,
    );
    // ... rest of function
}
```

### Proof of Concept

1. Staker `S` is active and past the K-epoch delay (balance is non-zero).
2. Consensus rewards are enabled (`is_pre_consensus()` returns `false`).
3. Attacker `A` (any EOA) calls `update_rewards(S, disable_rewards: true)` in block `N`.
4. Execution reaches line 1485: `self.last_reward_block.write(N)`.
5. Execution hits `if disable_rewards || self.is_pre_consensus() { return; }` — exits with no rewards written.
6. Sequencer calls `update_rewards(S, disable_rewards: false)` in the same block `N`.
7. Line 1454 asserts `N > last_reward_block` → `N > N` → **false** → reverts `REWARDS_ALREADY_UPDATED`.
8. Block `N` rewards are permanently lost for staker `S` and all its delegators. [5](#0-4)

### Citations

**File:** docs/spec.md (L1644-1645)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
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

**File:** src/staking/interface.cairo (L303-311)
```text
#[starknet::interface]
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```
