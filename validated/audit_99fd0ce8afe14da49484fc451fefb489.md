### Title
Missing Access Control on `update_rewards` Allows Any Caller to Permanently Freeze Consensus Rewards for All Stakers — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in the Staking contract has no caller access control. Any unprivileged address can invoke it with `disable_rewards=true` and a valid staker address every block, consuming the global `last_reward_block` slot without distributing any rewards. Because `last_reward_block` is a single contract-wide variable, this permanently prevents all stakers from receiving consensus-era block rewards.

---

### Finding Description

`update_rewards` is exposed as a public ABI function via `StakingRewardsManagerImpl`:

```cairo
#[abi(embed_v0)]
impl StakingRewardsManagerImpl of IStakingRewardsManager<ContractState> {
    fn update_rewards(
        ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
    ) {
        self.general_prerequisites();          // only checks: not paused, caller != zero
        let current_block_number = starknet::get_block_number();
        assert!(
            current_block_number > self.last_reward_block.read(),
            "{}",
            Error::REWARDS_ALREADY_UPDATED,
        );
        ...
        self.last_reward_block.write(current_block_number);   // global write

        if disable_rewards || self.is_pre_consensus() {
            return;                            // exits without distributing rewards
        }
        ...
    }
}
``` [1](#0-0) 

`general_prerequisites` enforces only two conditions — the contract is not paused and the caller is not the zero address: [2](#0-1) 

`last_reward_block` is a single global storage slot, not per-staker: [3](#0-2) 

The assertion `current_block_number > self.last_reward_block.read()` means only **one** call to `update_rewards` can succeed per block across the entire contract. Once the slot is consumed, every other call in that block reverts with `REWARDS_ALREADY_UPDATED`. [4](#0-3) 

By contrast, the pre-consensus reward path (`update_rewards_from_attestation_contract`) is correctly gated: [5](#0-4) 

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

An attacker who calls `update_rewards(any_active_staker, disable_rewards=true)` on every block:

1. Writes the current block number into `last_reward_block`.
2. Returns immediately without crediting any staker's `unclaimed_rewards_own` or forwarding pool rewards.
3. Blocks every legitimate call to `update_rewards` for that block (they all revert with `REWARDS_ALREADY_UPDATED`).

Repeating this every block means **no staker ever accumulates consensus-era block rewards**. The rewards are not deferred — they are simply never computed or stored. Stakers cannot recover the missed rewards for past blocks.

---

### Likelihood Explanation

**High.** The entry point is fully public. The attacker needs only:
- A non-zero address (any EOA or contract).
- The address of any currently active staker (readable from on-chain events or `get_stakers`).
- Gas to submit one transaction per block.

There is no economic barrier, no role requirement, and no time-lock. The attack is sustainable indefinitely.

---

### Recommendation

Add a role check to `update_rewards` so that only a trusted caller (e.g., the attestation contract, or a dedicated `REWARDS_MANAGER` role) can invoke it. The simplest fix mirrors the pattern already used in `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
+   self.assert_caller_is_attestation_contract(); // or a dedicated role
    ...
}
```

Alternatively, remove the `disable_rewards` parameter from the public interface entirely and handle that logic internally or through a privileged path.

---

### Proof of Concept

```
// Attacker script (pseudocode, one call per block):
loop every block:
    staking_contract.update_rewards(
        staker_address = <any_valid_active_staker>,
        disable_rewards = true
    )
    // Effect:
    //   last_reward_block := current_block
    //   no rewards distributed
    //   all other update_rewards calls in this block revert
```

Step-by-step:

1. Attacker picks any active staker address (e.g., from `NewStaker` events).
2. Each block, attacker calls `update_rewards(staker, true)`.
3. `last_reward_block` is set to the current block; the function returns early.
4. Any legitimate call to `update_rewards` in the same block fails with `REWARDS_ALREADY_UPDATED`.
5. No staker receives consensus block rewards for that block.
6. Repeated every block → all consensus rewards are permanently frozen.

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1393-1401)
```text
    impl StakingAttestationImpl of IStakingAttestation<ContractState> {
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
