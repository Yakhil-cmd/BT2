### Title
Unrestricted `update_rewards` with `disable_rewards: true` Enables Permanent Griefing of Consensus Reward Distribution - (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract has no caller access control and accepts a caller-supplied `disable_rewards` boolean. Any unprivileged address can call `update_rewards(staker_address: <any_valid_staker>, disable_rewards: true)` once per block, consuming the global `last_reward_block` slot without distributing any rewards. Because the contract enforces a strict one-call-per-block invariant via `last_reward_block`, a griefing attacker can permanently prevent every legitimate staker from receiving consensus rewards at negligible cost.

---

### Finding Description

`update_rewards` is declared in `IStakingRewardsManager` and is a fully public entry point. Its only gate is `general_prerequisites()`, which checks only that the contract is unpaused and the caller is non-zero — no staker identity check, no role check. [1](#0-0) 

The function immediately writes `last_reward_block` to the current block number **before** checking `disable_rewards`: [2](#0-1) 

If `disable_rewards` is `true`, the function returns early — no rewards are calculated or distributed — but `last_reward_block` has already been advanced: [3](#0-2) 

The one-call-per-block invariant is enforced at the top of the function: [4](#0-3) 

**Attack sequence (per block):**

1. Attacker picks any V3-migrated staker with non-zero STRK balance (publicly readable from chain state).
2. Attacker calls `update_rewards(staker_address: victim_staker, disable_rewards: true)`.
3. `last_reward_block` is set to the current block; no rewards are distributed.
4. Any legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. Repeat every block.

The attacker needs no stake, no special role, and no privileged key — only the ability to submit one transaction per block.

---

### Impact Explanation

Consensus rewards (`is_pre_consensus() == false`) are distributed exclusively through `update_rewards`. By monopolising `last_reward_block` every block with `disable_rewards: true`, the attacker causes **all stakers' unclaimed consensus rewards to be permanently frozen** for as long as the attack continues. Stakers accumulate zero rewards despite having active stake and performing valid attestations. This matches the **High** impact tier: *Permanent/Temporary freezing of unclaimed yield*. [5](#0-4) [6](#0-5) 

---

### Likelihood Explanation

- **No privilege required**: `general_prerequisites()` only checks pause state and non-zero caller.
- **Cheap to execute**: One transaction per block; gas cost is trivial compared to the aggregate rewards denied to all stakers.
- **Permissionless target selection**: Any active V3 staker address (readable from the public `stakers` vector) can be used as `staker_address`.
- **No detection/prevention on-chain**: The contract has no rate-limiting, no whitelist, and no mechanism to distinguish a legitimate call from a griefing call when `disable_rewards: true`.

Likelihood is **Medium** (requires sustained effort) but the cost/impact ratio makes it economically rational for a competitor or malicious actor.

---

### Recommendation

1. **Restrict the caller**: Only the staker themselves, their registered `reward_address`, or an explicitly whitelisted consensus contract should be permitted to call `update_rewards`. Add an assertion such as:
   ```cairo
   assert!(
       caller == staker_address || caller == staker_info.reward_address,
       "{}",
       Error::UNAUTHORIZED_CALLER,
   );
   ```
2. **Decouple `last_reward_block` update from `disable_rewards`**: Do not advance `last_reward_block` when `disable_rewards: true` unless the caller is authorised to disable rewards.
3. **Audit `disable_rewards` semantics**: If `disable_rewards` is intended only for protocol-internal use (e.g., penalisation), gate it behind a role check rather than exposing it as a free parameter.

---

### Proof of Concept

```
// Attacker script (pseudocode, runs every block)
let valid_staker = staking.stakers[0];  // any active V3 staker
staking.update_rewards(
    staker_address: valid_staker,
    disable_rewards: true,   // no rewards distributed
);
// last_reward_block == current_block
// All other update_rewards calls this block revert with REWARDS_ALREADY_UPDATED
```

Concrete on-chain steps:
1. Read `stakers` vector from `Staking` storage to obtain a valid V3 staker address.
2. Each block, submit `update_rewards(staker_address: <valid_staker>, disable_rewards: true)` from any EOA.
3. Observe that `StakerRewardsUpdated` events cease for all stakers.
4. Confirm `last_reward_block` equals the current block after each attacker transaction.
5. Confirm no legitimate `update_rewards` call succeeds in the same block. [7](#0-6) [8](#0-7)

### Citations

**File:** src/staking/staking.cairo (L1378-1381)
```text
        fn disable_token(ref self: ContractState, token_address: ContractAddress) {
            self.roles.only_security_agent();
            let is_active_opt: Option<(Epoch, bool)> = self.btc_tokens.read(token_address);
            assert!(is_active_opt.is_some(), "{}", Error::TOKEN_NOT_EXISTS);
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

**File:** src/staking/staking.cairo (L1792-1797)
```text

        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
