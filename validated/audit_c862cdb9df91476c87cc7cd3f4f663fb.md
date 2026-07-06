### Title
Attacker-Controlled `disable_rewards` Parameter in `update_rewards` Enables Permanent Freezing of All Consensus Rewards — (File: `src/staking/staking.cairo`)

---

### Summary

The public `update_rewards` function in the `Staking` contract accepts a caller-controlled `disable_rewards: bool` parameter with no access control. When called with `disable_rewards: true`, the function consumes the current block's reward slot by writing `last_reward_block` to the current block number, but skips all reward distribution. Because `last_reward_block` is a single global value, any subsequent legitimate call in the same block is rejected with `REWARDS_ALREADY_UPDATED`. An unprivileged attacker can call this every block to permanently freeze all consensus rewards for all stakers.

---

### Finding Description

`update_rewards` is a public, permissionless function callable by any non-zero address: [1](#0-0) 

The function first checks that the current block has not yet been processed: [2](#0-1) 

It then unconditionally writes the current block number to the global `last_reward_block` storage slot: [3](#0-2) 

Immediately after, if the caller-supplied `disable_rewards` is `true`, the function returns early without distributing any rewards: [4](#0-3) 

The `general_prerequisites` guard only checks that the contract is unpaused and the caller is non-zero — no role or identity check: [5](#0-4) 

The `last_reward_block` field is a single global value shared across all stakers: [6](#0-5) 

Because the block slot is consumed before the early return, no other caller can distribute rewards for that block. An attacker who calls `update_rewards(any_valid_staker, true)` at every block permanently prevents all consensus reward distribution.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Consensus rewards (`_update_rewards` path) are the primary reward mechanism in V3. By consuming every block's reward slot with `disable_rewards: true`, an attacker causes all stakers to accrue zero rewards indefinitely. The `unclaimed_rewards` in the `RewardSupplier` never grows from block-based calls, and stakers' `unclaimed_rewards_own` fields are never incremented. This constitutes permanent freezing of unclaimed yield for the entire protocol. [7](#0-6) 

---

### Likelihood Explanation

**High.** The attack requires no stake, no privileged role, and no special setup. The attacker only needs to:
1. Know any valid, active staker address (publicly observable from `NewStaker` events).
2. Submit one transaction per block with `disable_rewards: true`.

Gas cost is the only barrier. The attack is sustainable and profitable for any party that benefits from suppressing staking rewards (e.g., a competing protocol or a short-seller of STRK).

---

### Recommendation

Remove the `disable_rewards` parameter from the public interface entirely, or restrict it to a privileged role (e.g., `only_security_agent`). If the parameter is needed for legitimate protocol operations (e.g., during migration), gate it behind an access control check:

```cairo
fn update_rewards(ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool) {
    if disable_rewards {
        self.roles.only_security_agent(); // or equivalent privileged role
    }
    ...
}
```

Alternatively, remove the parameter and derive `disable_rewards` from on-chain state only (e.g., a governance-controlled flag), so no caller can inject it.

---

### Proof of Concept

```
// Attacker script (pseudocode, runs every block):
loop {
    wait_for_new_block();
    // Pick any known active staker address from on-chain events
    let victim_staker = 0xABCD...;
    staking_contract.update_rewards(
        staker_address: victim_staker,
        disable_rewards: true   // <-- attacker-injected parameter
    );
    // last_reward_block is now set to current block.
    // No rewards distributed.
    // Any legitimate update_rewards call this block fails: REWARDS_ALREADY_UPDATED.
}
```

**Step-by-step:**
1. Attacker calls `update_rewards(valid_staker, true)` at block N.
2. `assert!(current_block_number > self.last_reward_block.read())` passes (first call this block).
3. `self.last_reward_block.write(N)` executes — slot consumed.
4. `if disable_rewards { return; }` — no rewards distributed.
5. Any honest node or staker calling `update_rewards` at block N now hits `REWARDS_ALREADY_UPDATED` and reverts.
6. Repeated every block: all stakers receive zero consensus rewards permanently. [8](#0-7)

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
