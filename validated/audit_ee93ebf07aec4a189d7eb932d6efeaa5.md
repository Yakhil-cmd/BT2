### Title
Unrestricted `update_rewards` Allows Any Caller to Permanently Freeze or Misroute Block Rewards — (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract carries no caller restriction. Combined with the global `last_reward_block` guard that permits only one reward-distribution call per block, any unprivileged actor can either (a) permanently freeze all consensus-era block rewards by calling with `disable_rewards = true` every block, or (b) route each block's rewards to their own staker address, starving every other staker of yield.

---

### Finding Description

`update_rewards` is the sole mechanism for distributing per-block rewards in the consensus-rewards era. It is declared in `IStakingRewardsManager` and implemented in `src/staking/staking.cairo` starting at line 1449.

```cairo
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
    ...
    self.last_reward_block.write(current_block_number);   // ← consumes the slot for this block
    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← no rewards distributed
    }
    ...
    self._update_rewards(:staker_address, ...);            // ← rewards go to caller-chosen staker
}
```

There is **no `assert_caller_is_attestation_contract` or equivalent guard**. The function accepts an arbitrary `staker_address` from any caller and an arbitrary `disable_rewards` flag.

**Attack vector A — permanent reward freeze:**
An attacker calls `update_rewards(any_active_staker, true)` as the first transaction of every block. The call:
1. Passes all checks (staker exists, block is new).
2. Writes `current_block_number` into `last_reward_block`, consuming the per-block slot.
3. Returns immediately because `disable_rewards == true`, distributing nothing.

Every subsequent legitimate call in that block reverts with `REWARDS_ALREADY_UPDATED`. No staker ever receives consensus-era block rewards.

**Attack vector B — reward theft:**
An attacker who is a registered staker calls `update_rewards(attacker_address, false)` as the first transaction of every block. The block's full reward is credited to the attacker's staker record. The legitimate attester for that block cannot call the function (slot already consumed) and receives nothing.

The contrast with the pre-consensus path makes the missing guard obvious. `update_rewards_from_attestation_contract` (line 1394) correctly asserts the caller is the attestation contract:

```cairo
fn update_rewards_from_attestation_contract(
    ref self: ContractState, staker_address: ContractAddress,
) {
    ...
    self.assert_caller_is_attestation_contract();   // ← guard present here
    ...
}
```

`update_rewards` has no analogous guard.

---

### Impact Explanation

**Attack A** — Permanent freezing of unclaimed yield (High). Every staker and pool member in the consensus-rewards era is denied all block rewards indefinitely. The `last_reward_block` slot is consumed each block with zero distribution; the rewards are never minted or transferred.

**Attack B** — Theft of unclaimed yield (High). The attacker accumulates block rewards for every block, far exceeding their proportional entitlement. All other stakers receive zero block rewards for those blocks.

Both impacts fall within the allowed scope: *"Theft of unclaimed yield"* and *"Permanent freezing of unclaimed yield"*.

---

### Likelihood Explanation

- The function is public and requires no special role, token balance beyond the minimum stake (for Attack B), or privileged access.
- Attack A requires only a valid active staker address (publicly readable from `stakers` vector) and costs only the gas for one transaction per block.
- Attack B requires the attacker to be a registered staker, which is permissionless.
- In Starknet's current sequencer model the attacker must have their transaction ordered before the legitimate attestation call within the same block; this is feasible given that transaction ordering is not guaranteed to favour the attester.

---

### Recommendation

Add a caller restriction identical to the one already present in `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
+   self.assert_caller_is_attestation_contract();
    ...
}
```

Alternatively, derive `staker_address` from the attestation contract's call rather than accepting it as a free parameter, eliminating the ability to route rewards to an arbitrary staker.

---

### Proof of Concept

1. Deploy the protocol in consensus-rewards mode (`consensus_rewards_first_epoch` set, `is_pre_consensus()` returns `false`).
2. Register attacker as a staker with the minimum stake.
3. Each block, before the legitimate attestation transaction is processed, submit:
   ```
   staking.update_rewards(attacker_address, true)   // Attack A: freeze
   // or
   staking.update_rewards(attacker_address, false)  // Attack B: steal
   ```
4. **Attack A result**: `last_reward_block` is updated; the legitimate attestation call reverts with `REWARDS_ALREADY_UPDATED`; no rewards are ever distributed.
5. **Attack B result**: `_update_rewards` credits the full block reward to the attacker's staker record; the legitimate attester's call reverts; the attacker accumulates rewards for every block. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L1394-1423)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);

            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();
            // Get current epoch data.
            let (strk_epoch_rewards, btc_epoch_rewards) = reward_supplier_dispatcher
                .calculate_current_epoch_rewards();
            let (strk_total_stake, btc_total_stake) = self.get_current_total_staking_power();
            let staker_pool_info = self.staker_pool_info.entry(staker_address).as_non_mut();
            let curr_epoch = self.get_current_epoch();
            self
                ._update_rewards(
                    :staker_address,
                    strk_total_rewards: strk_epoch_rewards,
                    btc_total_rewards: btc_epoch_rewards,
                    :strk_total_stake,
                    :btc_total_stake,
                    :staker_info,
                    :staker_pool_info,
                    :reward_supplier_dispatcher,
                    :curr_epoch,
                );
        }
```

**File:** src/staking/staking.cairo (L1449-1500)
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
```
