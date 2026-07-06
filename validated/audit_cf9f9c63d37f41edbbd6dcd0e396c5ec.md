### Title
Unrestricted `update_rewards` with `disable_rewards: true` Allows Permanent Griefing of All Staker Block Rewards — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract has no access control and accepts a caller-supplied `disable_rewards` flag. The global `last_reward_block` counter is written **before** the `disable_rewards` guard is evaluated. Any unprivileged caller can invoke `update_rewards(any_staker, disable_rewards: true)` once per block to consume the per-block reward slot without distributing rewards, permanently blocking all stakers from receiving consensus block rewards.

---

### Finding Description

`update_rewards` is the entry point through which the consensus mechanism distributes per-block STRK/BTC rewards to stakers in V3 (post-`consensus_rewards_first_epoch`) mode.

```cairo
// src/staking/staking.cairo  lines 1449–1507
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
    // ... staker existence / active / non-zero balance checks ...

    // *** last_reward_block is written HERE, before the disable_rewards guard ***
    self.last_reward_block.write(current_block_number);   // line 1485

    if disable_rewards || self.is_pre_consensus() {       // line 1487
        return;                                           // exits with NO rewards distributed
    }
    // ... actual reward calculation and distribution ...
}
```

Two structural properties combine to create the vulnerability:

1. **No access control.** `general_prerequisites()` only asserts the contract is unpaused and the caller is non-zero. There is no role check.

2. **Global `last_reward_block` is consumed before the `disable_rewards` guard.** `last_reward_block` is a single contract-wide storage slot:

```cairo
// src/staking/staking.cairo  line 187
last_reward_block: BlockNumber,
```

Because it is global, one call with `disable_rewards: true` in block N sets `last_reward_block = N` for **every staker**. Any subsequent call in block N — including the legitimate consensus call — hits the `REWARDS_ALREADY_UPDATED` assertion and reverts.

This is the direct analog of the HatsSignerGate bug: just as `reconcileSignerCount()` could reduce `safe.getThreshold()` below `minThreshold` so that `checkTransaction()` passed both existing checks while the real signer count was below the minimum, here `update_rewards(_, disable_rewards: true)` consumes the per-block reward slot so that the real reward-distributing call is blocked — while all existing guards (staker active, non-zero balance, block number check) still pass.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker who submits `update_rewards(any_valid_staker, disable_rewards: true)` as the first transaction in every block:

- Consumes the global `last_reward_block` slot with no reward distribution.
- Forces every legitimate consensus reward call in that block to revert with `REWARDS_ALREADY_UPDATED`.
- Repeating this every block permanently prevents all stakers from accruing consensus block rewards.

Because `last_reward_block` is global, a single cheap call per block is sufficient to freeze rewards for the entire protocol, not just one staker.

---

### Likelihood Explanation

**Medium.** The attack requires one transaction per block. On Starknet, transaction fees are low. A competitor, a griefing actor, or a protocol adversary with modest capital can sustain this indefinitely. No privileged key, bridge compromise, or external dependency is required — only a non-zero address and enough STRK for gas.

---

### Recommendation

Move `last_reward_block.write(current_block_number)` to **after** the `disable_rewards` guard, so the slot is only consumed when rewards are actually distributed:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
// Only mark the block as processed when rewards are actually distributed.
self.last_reward_block.write(current_block_number);
// ... reward calculation ...
```

Alternatively, add an access-control check (e.g., `only_app_governor` or a dedicated `REWARDS_MANAGER` role) so that only the authorized consensus caller can invoke `update_rewards`.

---

### Proof of Concept

1. Consensus rewards are active (`current_epoch >= consensus_rewards_first_epoch`).
2. Attacker (any EOA) calls `update_rewards(staker_A, disable_rewards: true)` in block N.
   - `last_reward_block` is written to N.
   - No rewards are distributed.
3. The legitimate consensus call `update_rewards(staker_A, disable_rewards: false)` in block N reverts: `current_block_number (N) > last_reward_block (N)` is **false**.
4. Attacker repeats in block N+1, N+2, …
5. No staker ever receives consensus block rewards; all unclaimed yield is permanently frozen. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
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
