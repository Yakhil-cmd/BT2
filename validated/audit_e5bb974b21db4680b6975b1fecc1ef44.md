### Title
Missing Caller Authorization in `update_rewards` Allows Any Address to Permanently Suppress Per-Block Rewards - (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in `StakingRewardsManagerImpl` is documented as restricted to "Only starkware sequencer" but contains **no caller check** in the implementation. Any unprivileged address can call it with `disable_rewards: true`, which atomically marks the current block as "already rewarded" via the global `last_reward_block` storage variable and returns without distributing any rewards. Because `last_reward_block` is global (not per-staker), this permanently discards that block's rewards for every staker — no subsequent call in the same block can succeed.

---

### Finding Description

The spec at `docs/spec.md` line 1645 states:

> **access control**: Only starkware sequencer.

The production implementation at `src/staking/staking.cairo` lines 1449–1507 is:

```rust
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();          // only checks is_paused
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    // ... staker validity checks ...
    self.last_reward_block.write(current_block_number);   // ← global write
    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← no rewards distributed
    }
    // ... reward distribution ...
}
```

`general_prerequisites()` only asserts the contract is not paused — there is no `only_sequencer`, role check, or `get_caller_address()` guard anywhere in this function. [1](#0-0) 

The global `last_reward_block` is written **before** the `disable_rewards` branch, so even when rewards are suppressed, the block is permanently marked as processed. [2](#0-1) 

The spec's stated access control is not implemented: [3](#0-2) 

---

### Impact Explanation

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` in block N:

1. Passes the `REWARDS_ALREADY_UPDATED` guard (first call in that block).
2. Writes `last_reward_block = N`.
3. Returns immediately — zero rewards distributed to any staker or pool.
4. Any subsequent call in block N (including the legitimate sequencer's call) reverts with `REWARDS_ALREADY_UPDATED`.

Block N's rewards are **permanently lost** — there is no catch-up mechanism. The attacker can repeat this every block, continuously zeroing out all staker and pool yield. This matches the **High: Permanent freezing of unclaimed yield** impact category. [4](#0-3) 

---

### Likelihood Explanation

The function is part of the public ABI (`#[abi(embed_v0)]` on `StakingRewardsManagerImpl`). Any Starknet account can submit a transaction calling it. The only precondition is that the chosen `staker_address` is an active staker with non-zero balance — trivially satisfiable by observing any existing staker on-chain. The attacker needs no funds beyond gas. [5](#0-4) 

---

### Recommendation

Add a sequencer/role guard at the top of `update_rewards`, consistent with every other privileged config function in the contract (e.g., `set_min_stake` uses `self.roles.only_token_admin()`):

```rust
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.roles.only_sequencer();   // add this
    self.general_prerequisites();
    ...
}
```

Alternatively, restrict via the existing roles framework to whichever role corresponds to "starkware sequencer." [6](#0-5) 

---

### Proof of Concept

```
1. Deploy staking contract with consensus rewards active.
2. Stake as StakerA (legitimate validator, active with non-zero balance).
3. Advance to a new block.
4. Attacker (any EOA) calls:
       staking.update_rewards(staker_address=StakerA, disable_rewards=true)
   → Succeeds. last_reward_block = current_block. No rewards distributed.
5. Legitimate sequencer calls:
       staking.update_rewards(staker_address=StakerA, disable_rewards=false)
   → Reverts: REWARDS_ALREADY_UPDATED.
6. StakerA's unclaimed_rewards_own is unchanged. Block rewards are gone.
7. Repeat step 3–6 for every block → StakerA accumulates zero yield indefinitely.
```

This is directly confirmed by the existing test at `src/staking/tests/test.cairo` lines 3956–3973, which shows that calling `update_rewards` with `disable_rewards: true` followed by `disable_rewards: false` in the same block always reverts the second call — the test uses a privileged caller only by convention, not enforcement. [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L1269-1273)
```text
    #[abi(embed_v0)]
    impl StakingConfigImpl of IStakingConfig<ContractState> {
        fn set_min_stake(ref self: ContractState, min_stake: Amount) {
            self.roles.only_token_admin();
            let old_min_stake = self.min_stake.read();
```

**File:** src/staking/staking.cairo (L1447-1489)
```text
    #[abi(embed_v0)]
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
```

**File:** docs/spec.md (L1644-1646)
```markdown
#### access control <!-- omit from toc -->
Only starkware sequencer.
#### logic <!-- omit from toc -->
```

**File:** src/staking/tests/test.cairo (L3956-3973)
```text
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: false);
    // Catch REWARDS_ALREADY_UPDATED.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());

    advance_epoch_global();
    staking_rewards_dispatcher.update_rewards(:staker_address, disable_rewards: true);
    // Catch REWARDS_ALREADY_UPDATE - with distribute = false.
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: true);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
    let result = staking_rewards_safe_dispatcher
        .update_rewards(:staker_address, disable_rewards: false);
    assert_panic_with_error(:result, expected_error: Error::REWARDS_ALREADY_UPDATED.describe());
```
