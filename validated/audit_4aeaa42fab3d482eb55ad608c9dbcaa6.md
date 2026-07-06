### Title
Unvalidated `disable_rewards` Parameter in Public `update_rewards` Allows Any Caller to Permanently Deny Block Rewards to Stakers — (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in the Staking contract is publicly callable by any non-zero address and accepts an attacker-controlled `disable_rewards: bool` parameter with no access control. When called with `disable_rewards: true`, the function advances the global `last_reward_block` to the current block but skips reward distribution entirely. Because `last_reward_block` is a single global storage slot, any subsequent call to `update_rewards` in the same block fails with `REWARDS_ALREADY_UPDATED`. An attacker can front-run the legitimate staker's call, causing permanent loss of that block's rewards.

---

### Finding Description

`update_rewards` is defined in `src/staking/staking.cairo` under `StakingRewardsManagerImpl`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();                          // only checks: not paused, caller != 0
    let current_block_number = starknet::get_block_number();
    assert!(
        current_block_number > self.last_reward_block.read(),
        "{}",
        Error::REWARDS_ALREADY_UPDATED,
    );
    ...
    // Update last block rewards.
    self.last_reward_block.write(current_block_number);   // ← written BEFORE the guard below

    if disable_rewards || self.is_pre_consensus() {
        return;                                            // ← exits without distributing rewards
    }
    ...
``` [1](#0-0) 

`general_prerequisites` enforces only two conditions: the contract is not paused, and the caller is not the zero address. [2](#0-1) 

`last_reward_block` is a single global `BlockNumber` in storage — not a per-staker map:

```cairo
/// Last block number for which rewards were distributed.
last_reward_block: BlockNumber,
``` [3](#0-2) 

The sequence of operations is:
1. Assert `current_block > last_reward_block` (gate check).
2. Write `last_reward_block = current_block` — **unconditionally**, before the `disable_rewards` branch.
3. If `disable_rewards == true`, return immediately without distributing rewards.

Because step 2 happens before step 3, any attacker who calls `update_rewards(victim_staker, true)` first in a block will:
- Consume the block's single reward slot (the gate check will now fail for everyone else in the same block).
- Distribute zero rewards to the victim staker.

The victim staker's own call in the same block will revert with `REWARDS_ALREADY_UPDATED`, and the block rewards are permanently lost — there is no mechanism to retroactively claim rewards for a missed block.

---

### Impact Explanation

**High — Theft of unclaimed yield.**

In the V3 consensus-rewards model, each block is assigned to exactly one staker (determined by a Poseidon hash of stake, epoch, and staker address). That staker is expected to call `update_rewards` once per block to receive their block reward. Because `last_reward_block` is global and only one call per block is permitted, a successful front-run with `disable_rewards: true` permanently erases the staker's reward for that block. Repeated across many blocks, this constitutes systematic theft of unclaimed yield from targeted stakers. [4](#0-3) 

---

### Likelihood Explanation

**Medium.** The attack requires front-running: the attacker must observe the victim's pending `update_rewards` transaction and submit their own with higher priority. On Starknet, transaction ordering is controlled by the sequencer, so front-running is feasible for a motivated attacker (e.g., a competing validator or a griefing party). No privileged role, leaked key, or external dependency is required — any unprivileged address can call `update_rewards`.

---

### Recommendation

**Short term:** Add a caller-identity check so that only the staker's registered operational address (or the staker address itself) may call `update_rewards`. This mirrors the pattern already used in `attest` (which requires the operational address as the caller).

**Long term:** The `disable_rewards` parameter should not be part of the public ABI if it can be weaponized by third parties. Either remove it from the external interface and handle the "no-reward" case internally, or gate it behind an access-controlled role.

---

### Proof of Concept

```
Block N is assigned to Staker A (determined by Poseidon hash).

1. Staker A submits: update_rewards(staker_A, disable_rewards=false)

2. Attacker observes the pending tx and submits with higher priority:
       update_rewards(staker_A, disable_rewards=true)

3. Attacker's tx executes first:
   - last_reward_block is written to N
   - disable_rewards=true → function returns, no rewards distributed

4. Staker A's tx executes next:
   - assert!(current_block_number > last_reward_block.read())
     → current_block_number == N == last_reward_block → PANIC: REWARDS_ALREADY_UPDATED

5. Staker A permanently loses block-N rewards.
   There is no catch-up mechanism; the block reward slot is consumed and gone.
``` [5](#0-4)

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
