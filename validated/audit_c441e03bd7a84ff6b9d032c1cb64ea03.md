### Title
Unprivileged Caller Can Permanently Freeze All Stakers' Block Rewards via `update_rewards(disable_rewards: true)` — (File: `src/staking/staking.cairo`)

---

### Summary

`update_rewards` in `staking.cairo` is publicly callable by any non-zero address. It accepts a `disable_rewards` boolean that, when `true`, writes the global `last_reward_block` to the current block number **before** the early-return guard, then exits without distributing rewards. Because `last_reward_block` is a single contract-wide variable, every subsequent `update_rewards` call in the same block reverts with `REWARDS_ALREADY_UPDATED`, permanently denying consensus block rewards to all stakers for that block.

---

### Finding Description

`update_rewards` is exposed through `IStakingRewardsManager` with `#[abi(embed_v0)]` and is gated only by `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero — no role restriction. [1](#0-0) 

The critical ordering inside the function is:

1. Assert `current_block_number > last_reward_block` (global, not per-staker).
2. Validate the staker exists, is active, and has non-zero STRK balance.
3. **Write `last_reward_block = current_block_number`** — this happens unconditionally.
4. `if disable_rewards || self.is_pre_consensus() { return; }` — exits without distributing any rewards. [2](#0-1) 

Step 3 commits the state change before the `disable_rewards` guard in step 4. Once `last_reward_block` equals the current block, the assertion in step 1 will revert every subsequent call in that block: [3](#0-2) 

The attacker only needs to supply any valid, active staker address with non-zero STRK balance — all of which are public on-chain. The `staker_address` parameter is irrelevant to the global `last_reward_block` side-effect. [4](#0-3) 

---

### Impact Explanation

After consensus rewards are activated (`!is_pre_consensus()`), an attacker who front-runs every block with `update_rewards(any_valid_staker, disable_rewards: true)` causes `last_reward_block` to be stamped without any reward distribution. All stakers and their delegation pools permanently lose the block rewards for every such block. The rewards are never queued for later recovery — they are simply never calculated or transferred. This constitutes **permanent freezing of unclaimed yield** for all stakers.

---

### Likelihood Explanation

- No privileged role is required; any EOA or contract with a non-zero address can call `update_rewards`.
- The attacker only needs to know one active staker address, which is trivially observable from on-chain events (`NewStaker`).
- The cost is one transaction per block. On Starknet, transaction fees are low, making sustained griefing economically viable.
- There is no on-chain mechanism to detect or revert the damage after the fact.

---

### Recommendation

Restrict who may supply `disable_rewards: true`. Options include:

1. **Access-control gate**: Require the caller to be the staker themselves, their reward address, or a privileged role before accepting `disable_rewards: true`.
2. **Remove the public parameter**: Move `disable_rewards` logic to an internal function callable only by trusted contracts (e.g., the attestation contract or a governance role).
3. **Write `last_reward_block` only after the `disable_rewards` check**: If `disable_rewards` is `true`, return before committing the state change, so the block remains claimable by a legitimate caller.

---

### Proof of Concept

```
// Attacker observes any active staker address S (from NewStaker events).
// In every block N after consensus rewards are activated:

1. Attacker calls: staking.update_rewards(staker_address=S, disable_rewards=true)
   - Passes: current_block_number (N) > last_reward_block (N-1) ✓
   - Passes: S is a valid, active staker with non-zero STRK balance ✓
   - Writes: last_reward_block = N
   - Returns early: no rewards distributed

2. Legitimate staker (or anyone) calls: staking.update_rewards(staker_address=S, disable_rewards=false)
   - Fails: current_block_number (N) > last_reward_block (N) → REWARDS_ALREADY_UPDATED ✗

Result: All stakers lose block rewards for block N. Repeating this every block
        permanently freezes all consensus block rewards for the entire protocol.
``` [5](#0-4)

### Citations

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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
