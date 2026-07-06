### Title
Unprivileged Caller Can Permanently Freeze Block Rewards by Passing `disable_rewards: true` to `update_rewards` - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the `Staking` contract is publicly callable with no access control. Any unprivileged caller can invoke it with `disable_rewards: true`, which causes `last_reward_block` to be written to the current block number **before** the `disable_rewards` guard is evaluated. This permanently consumes the per-block reward slot, preventing any subsequent legitimate call in the same block from distributing rewards. Repeated across blocks, this permanently freezes all consensus-era unclaimed yield for every staker and pool member.

---

### Finding Description

`IStakingRewardsManager::update_rewards` is gated only by `general_prerequisites()`, which checks the pause flag and that the caller is non-zero — no role or identity check is performed. [1](#0-0) 

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();          // only: not paused + caller != 0
    let current_block_number = starknet::get_block_number();
```

The function then writes `last_reward_block` to the current block number **unconditionally**, before the `disable_rewards` branch: [2](#0-1) 

```cairo
    // Update last block rewards.
    self.last_reward_block.write(current_block_number);

    if disable_rewards || self.is_pre_consensus() {
        return;
    }
```

If `disable_rewards` is `true`, the function returns immediately after marking the block as processed, distributing zero rewards. Any subsequent call in the same block hits: [3](#0-2) 

```cairo
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
```

and reverts. The reward slot for that block is permanently consumed with no yield distributed.

The `general_prerequisites` helper confirms there is no role guard: [4](#0-3) 

```cairo
fn general_prerequisites(ref self: ContractState) {
    self.assert_is_unpaused();
    assert_caller_is_not_zero();
}
```

---

### Impact Explanation

In the consensus rewards model, one call to `update_rewards` per block is the sole mechanism by which STRK (and BTC) block rewards are credited to stakers and forwarded to delegation pools via `_update_rewards` → `update_pool_rewards` → `pool.update_rewards_from_staking_contract`. [5](#0-4) 

If an attacker front-runs every block with `update_rewards(valid_staker, disable_rewards: true)`, no rewards are ever distributed. Because `last_reward_block` is a single global slot, one poisoned call per block is sufficient to freeze yield for **all** stakers and **all** pool members permanently. This matches the **High** impact category: *Permanent freezing of unclaimed yield*.

---

### Likelihood Explanation

- The function is fully public; no special role, key, or token is required.
- The attacker only needs to supply any currently-active staker address (readable from on-chain events or `get_stakers`).
- The cost is one transaction per block. On Starknet the sequencer controls ordering, but the attacker can submit the transaction at the start of each block before the legitimate consensus node does. Even intermittent success (e.g., every few blocks) causes measurable, permanent yield loss.
- There is no economic barrier: the attacker gains nothing but causes direct, irreversible harm to all protocol participants.

---

### Recommendation

Restrict `update_rewards` to a trusted caller — either the consensus/attestation contract or a designated operator role — consistent with how `update_rewards_from_attestation_contract` is protected: [6](#0-5) 

```cairo
fn update_rewards_from_attestation_contract(...) {
    ...
    self.assert_caller_is_attestation_contract();
    ...
}
```

Apply an equivalent `assert_caller_is_consensus_contract()` (or a dedicated role check) at the top of `update_rewards`. Alternatively, move the `self.last_reward_block.write(current_block_number)` call to **after** the `disable_rewards` guard so that a call with `disable_rewards: true` does not consume the block slot.

---

### Proof of Concept

1. Staking contract is in consensus-rewards mode (`is_pre_consensus()` returns `false`).
2. Attacker identifies any active staker address `S` with non-zero STRK balance (e.g., from `NewStaker` events).
3. At block `N`, attacker submits:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
4. `last_reward_block` is set to `N`; no rewards are distributed.
5. The legitimate consensus node submits `update_rewards(S, false)` in the same block → reverts with `REWARDS_ALREADY_UPDATED`.
6. All stakers and pool members receive zero rewards for block `N`.
7. Repeating step 3 every block permanently freezes all consensus-era yield.

### Citations

**File:** src/staking/staking.cairo (L1394-1401)
```text
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

**File:** src/staking/staking.cairo (L1448-1452)
```text
    impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
        fn update_rewards(
            ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
        ) {
            self.general_prerequisites();
```

**File:** src/staking/staking.cairo (L1453-1458)
```text
            let current_block_number = starknet::get_block_number();
            assert!(
                current_block_number > self.last_reward_block.read(),
                "{}",
                Error::REWARDS_ALREADY_UPDATED,
            );
```

**File:** src/staking/staking.cairo (L1484-1490)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }

```

**File:** src/staking/staking.cairo (L1491-1507)
```text
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

**File:** src/staking/staking.cairo (L1794-1797)
```text
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
