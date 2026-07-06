### Title
Unprivileged Caller Can Advance `last_reward_block` Without Distributing Rewards, Permanently Freezing Staker Yield — (File: `src/staking/staking.cairo`)

---

### Summary

`update_rewards` in the Staking contract is publicly callable with no access control. When called with `disable_rewards: true`, it unconditionally advances the global `last_reward_block` checkpoint **before** checking whether rewards should be distributed. Any unprivileged caller can exploit this to consume the per-block reward slot for every block, causing stakers to permanently lose their consensus-phase yield.

---

### Finding Description

`update_rewards` is exposed as a public ABI function via `StakingRewardsManagerImpl`: [1](#0-0) 

The function's logic is:

1. Call `general_prerequisites()` — only checks the contract is unpaused and caller is non-zero. No role check.
2. Assert `current_block_number > self.last_reward_block.read()`.
3. **Write `last_reward_block = current_block_number`** — the global checkpoint is advanced here, unconditionally.
4. Check `if disable_rewards || self.is_pre_consensus() { return; }` — if `disable_rewards` is `true`, the function returns early with no rewards distributed. [2](#0-1) 

The `general_prerequisites` guard: [3](#0-2) 

Because `last_reward_block` is a **single global value** shared across all stakers, advancing it without distributing rewards means no other call can distribute rewards for that block — the assertion at line 1455 will revert for any subsequent call in the same block. [4](#0-3) 

---

### Impact Explanation

An attacker calls `update_rewards(any_valid_staker_address, disable_rewards: true)` once per block. Each call:

- Advances `last_reward_block` to the current block.
- Distributes **zero** rewards.
- Blocks every legitimate `update_rewards(staker, false)` call in that block with `REWARDS_ALREADY_UPDATED`.

Stakers lose all consensus-phase block rewards for every block the attacker front-runs. If done continuously, this is **permanent freezing of unclaimed yield** for all stakers in the protocol — matching the High impact tier.

---

### Likelihood Explanation

- No special role or privilege is required; any EOA can call `update_rewards`.
- The only cost is gas per block.
- The attacker does not need to hold any stake or be a registered staker.
- The attack is straightforward to automate (one transaction per block).
- The victim stakers have no on-chain recourse once a block's slot is consumed.

---

### Recommendation

Move the `last_reward_block` write to **after** the `disable_rewards` / `is_pre_consensus` guard, so the checkpoint is only advanced when rewards are actually distributed:

```cairo
// Update last block rewards ONLY when rewards are actually distributed.
if disable_rewards || self.is_pre_consensus() {
    return;
}
self.last_reward_block.write(current_block_number);
// ... rest of reward distribution logic
```

Alternatively, restrict `update_rewards` to a trusted caller (e.g., the attestation contract or a designated operator role), consistent with how `update_rewards_from_attestation_contract` is already gated: [5](#0-4) 

---

### Proof of Concept

1. Protocol is in consensus-rewards phase (`is_pre_consensus()` returns `false`).
2. Staker `S` has non-zero balance and is active.
3. At block `N`, attacker calls `update_rewards(S, disable_rewards: true)`.
   - `last_reward_block` is written to `N`.
   - Function returns early; no rewards distributed.
4. Staker `S` (or anyone) calls `update_rewards(S, false)` in block `N`.
   - Assertion `current_block_number > last_reward_block` fails (`N > N` is false).
   - Transaction reverts with `REWARDS_ALREADY_UPDATED`.
5. Staker `S` permanently loses block `N` rewards.
6. Attacker repeats every block → all staker yield is frozen indefinitely. [6](#0-5)

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

**File:** src/staking/staking.cairo (L1793-1797)
```text
        /// Wrap initial operations required in any public staking function.
        fn general_prerequisites(ref self: ContractState) {
            self.assert_is_unpaused();
            assert_caller_is_not_zero();
        }
```
