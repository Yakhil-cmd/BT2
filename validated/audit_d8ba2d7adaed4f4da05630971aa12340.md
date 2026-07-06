### Title
Missing Caller Validation in `update_rewards` Allows Any Address to Freeze Staker Yield — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in `Staking.cairo` is a public external function that advances the global `last_reward_block` checkpoint and optionally distributes consensus-phase block rewards. It has no caller access-control check. Because `last_reward_block` is a single global value shared across all stakers, any unprivileged address can call `update_rewards` with `disable_rewards: true` every block, advancing the checkpoint without distributing any rewards and permanently blocking all legitimate reward updates for that block. The sibling function `update_rewards_from_attestation_contract` — which serves the same purpose in the pre-consensus phase — correctly enforces `assert_caller_is_attestation_contract()`. The consensus-phase counterpart is missing the equivalent guard.

---

### Finding Description

`update_rewards` is declared as a public ABI-embedded function in `StakingRewardsManagerImpl`: [1](#0-0) 

Its first substantive action after the generic pause/zero-address check is to write the current block number into the global `last_reward_block` storage slot: [2](#0-1) 

If `disable_rewards` is `true`, the function returns immediately after that write, distributing nothing: [3](#0-2) 

The guard that prevents a second call in the same block is: [4](#0-3) 

Because `last_reward_block` is global (not per-staker), a single call per block is sufficient to lock out every other caller for that block.

The pre-consensus analogue, `update_rewards_from_attestation_contract`, correctly restricts its caller: [5](#0-4) 

The helper that enforces that restriction exists and is reusable: [6](#0-5) 

`update_rewards` calls neither `assert_caller_is_attestation_contract` nor any equivalent role check.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker who calls `update_rewards(any_valid_staker, disable_rewards: true)` once per block:

1. Advances `last_reward_block` to the current block number.
2. Distributes zero rewards (early return at the `disable_rewards` branch).
3. Causes every subsequent legitimate call in the same block to revert with `REWARDS_ALREADY_UPDATED`.

Repeated across every block, this permanently prevents any staker from accumulating consensus-phase block rewards. All unclaimed yield that would have accrued via `_update_rewards` → `staker_info.unclaimed_rewards_own` is frozen indefinitely. [7](#0-6) 

---

### Likelihood Explanation

**High.** The function is unconditionally public (`#[abi(embed_v0)]`). No token balance, stake, or privileged role is required. The only precondition is supplying the address of any currently-active staker (readable from on-chain events or `get_stakers`). The per-block cost is a single cheap Starknet transaction. The attack is sustainable indefinitely by any motivated actor.

---

### Recommendation

Add a caller restriction to `update_rewards` that mirrors the one already present in `update_rewards_from_attestation_contract`. The appropriate guard depends on the intended consensus-phase caller (e.g., a designated consensus contract address stored in storage, analogous to `attestation_contract`). At minimum, introduce a stored `consensus_contract` address and assert:

```cairo
assert!(
    get_caller_address() == self.consensus_contract.read(),
    "{}",
    Error::CALLER_IS_NOT_CONSENSUS_CONTRACT,
);
```

This is the direct analog of the existing `assert_caller_is_attestation_contract` pattern. [6](#0-5) 

---

### Proof of Concept

```
// Attacker script (pseudocode, one call per block)
loop every block:
    staking_contract.update_rewards(
        staker_address = <any valid staker>,
        disable_rewards = true
    )
    // Effect: last_reward_block = current_block, rewards = 0
    // All legitimate update_rewards calls in this block now revert
    // with REWARDS_ALREADY_UPDATED
```

1. Attacker picks any address from the `stakers` vector (public storage).
2. Calls `update_rewards(staker_address, disable_rewards: true)` on the first transaction of each block.
3. `last_reward_block` is set to the current block; no rewards are written to `staker_info.unclaimed_rewards_own`.
4. Any consensus-layer call to `update_rewards` in the same block hits the `REWARDS_ALREADY_UPDATED` assertion and reverts.
5. All stakers accumulate zero yield for every block the attacker sustains the attack. [8](#0-7)

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

**File:** src/staking/staking.cairo (L2219-2225)
```text
        fn assert_caller_is_attestation_contract(self: @ContractState) {
            assert!(
                get_caller_address() == self.attestation_contract.read(),
                "{}",
                Error::CALLER_IS_NOT_ATTESTATION_CONTRACT,
            );
        }
```

**File:** src/staking/staking.cairo (L2361-2376)
```text
            // Update staker rewards.
            staker_info.unclaimed_rewards_own += staker_rewards;

            // Update pools rewards.
            let pool_rewards_list = self.update_pool_rewards(:staker_address, :pools_rewards_data);
            // Emit event.
            self
                .emit(
                    Events::StakerRewardsUpdated {
                        staker_address, staker_rewards, pool_rewards: pool_rewards_list.span(),
                    },
                );

            // Write staker rewards to storage.
            self.write_staker_info(:staker_address, :staker_info);
        }
```
