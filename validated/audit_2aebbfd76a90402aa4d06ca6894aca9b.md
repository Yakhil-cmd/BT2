### Title
Post-consensus `update_rewards` passes staker's individual balance as total-stake denominator, enabling disproportionate reward capture — (File: src/staking/staking.cairo)

---

### Summary

In the post-consensus `update_rewards` path, the staker's **individual** balance is passed as the `strk_total_stake` / `btc_total_stake` arguments to the shared internal `_update_rewards` helper. The pre-consensus path (`update_rewards_from_attestation_contract`) correctly passes the **global** total staking power to the same helper. Because `_update_rewards` uses those arguments as the denominator when computing each staker's proportional share, the post-consensus path causes the calling staker to receive the entire block reward rather than their proportional fraction.

---

### Finding Description

**Pre-consensus path — correct denominator:**

`update_rewards_from_attestation_contract` (lines 1394–1423) fetches the protocol-wide total staking power and forwards it to `_update_rewards`:

```cairo
// src/staking/staking.cairo  ~line 1408
let (strk_total_stake, btc_total_stake) = self.get_current_total_staking_power();
...
self._update_rewards(
    :staker_address,
    strk_total_rewards: strk_epoch_rewards,
    btc_total_rewards: btc_epoch_rewards,
    :strk_total_stake,          // ← global total
    :btc_total_stake,           // ← global total
    ...
);
```

**Post-consensus path — wrong denominator:**

`update_rewards` (lines 1449–1507) fetches only the **calling staker's** balance and passes it under the same parameter names:

```cairo
// src/staking/staking.cairo  ~line 1475
let (staker_total_strk_balance, staker_total_btc_balance) = self
    .get_staker_total_strk_btc_balance_at_epoch(
        :staker_address, :staker_pool_info, epoch_id: curr_epoch,
    );
...
self._update_rewards(
    :staker_address,
    strk_total_rewards: strk_block_rewards,
    btc_total_rewards: btc_block_rewards,
    strk_total_stake: staker_total_strk_balance,   // ← staker's own balance, NOT global total
    btc_total_stake: staker_total_btc_balance,     // ← staker's own balance, NOT global total
    ...
);
```

`_update_rewards` is a shared helper that computes the staker's proportional reward as:

```
staker_reward ≈ total_rewards × staker_balance / strk_total_stake
```

When `strk_total_stake == staker_balance` (as supplied by the post-consensus path), the ratio collapses to 1 and the staker receives **all** block rewards regardless of their actual share of the network stake.

The asymmetry is structurally identical to the external report: one code path (pre-consensus attestation) correctly excludes the staker's individual balance from the denominator, while the other code path (post-consensus `update_rewards`) includes only the staker's own balance as the denominator, producing an inflated reward.

---

### Impact Explanation

`update_rewards` is gated only by `general_prerequisites()` (pause check) and a per-block guard (`current_block_number > last_reward_block`). Any active staker can call it once per block with their own address. Because the denominator equals the numerator, the staker captures 100 % of the block reward for that block. Repeated every block, a single staker with even a minimal stake drains the entire reward stream, constituting **theft of unclaimed yield** from all other stakers and delegators.

This maps to the allowed impact: **High — Theft of unclaimed yield**.

---

### Likelihood Explanation

The function is publicly callable by any staker (no privileged role required). The post-consensus phase is the protocol's intended long-term operating mode. Once active, any staker who discovers the discrepancy can exploit it every block with a trivial on-chain call. Likelihood is **High**.

---

### Recommendation

In `update_rewards`, replace the staker-scoped balance variables with the global total staking power before forwarding to `_update_rewards`, mirroring the pre-consensus path:

```cairo
// Replace:
let (staker_total_strk_balance, staker_total_btc_balance) = self
    .get_staker_total_strk_btc_balance_at_epoch(...);
// assert non-zero (keep for the guard only)
assert!(staker_total_strk_balance.is_non_zero(), ...);

// Add:
let (strk_total_stake, btc_total_stake) = self
    .get_total_staking_power_at_epoch(epoch_id: curr_epoch);

// Then pass the global totals:
self._update_rewards(
    ...
    strk_total_stake: strk_total_stake,   // global, not staker-scoped
    btc_total_stake:  btc_total_stake,    // global, not staker-scoped
    ...
);
```

---

### Proof of Concept

1. Protocol transitions to post-consensus phase (`is_pre_consensus()` returns `false`).
2. Attacker (any registered staker, even with minimal stake) calls `update_rewards(attacker_address, false)` in block N.
3. Inside `update_rewards`:
   - `staker_total_strk_balance` = attacker's own balance, e.g. `min_stake` = X.
   - `strk_block_rewards` = total block reward for all stakers, e.g. R.
   - `_update_rewards` computes `attacker_reward = R × X / X = R`.
4. Attacker receives the full block reward R; all other stakers receive 0 for block N.
5. `last_reward_block` is set to N, preventing other stakers from calling in the same block.
6. In block N+1 the attacker repeats, draining the entire reward stream. [1](#0-0) [2](#0-1) [3](#0-2)

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
