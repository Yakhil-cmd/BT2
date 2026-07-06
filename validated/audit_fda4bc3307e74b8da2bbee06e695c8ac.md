### Title
Unprivileged Caller Can Permanently Freeze Consensus Block Rewards via `update_rewards(disable_rewards: true)` — (File: src/staking/staking.cairo)

---

### Summary

The `update_rewards` function in `StakingRewardsManagerImpl` is publicly callable with no access control. It writes to the global `last_reward_block` storage variable before checking the `disable_rewards` flag. Any unprivileged address can call `update_rewards(valid_staker, disable_rewards: true)` at the start of each block to consume the single per-block reward slot without distributing any rewards, permanently blocking all stakers from receiving consensus block rewards for that block.

---

### Finding Description

`update_rewards` is exposed as a public ABI function under `IStakingRewardsManager`. Its only access guard is `general_prerequisites()`, which checks that the contract is not paused and the caller is non-zero — no role or identity check is performed. [1](#0-0) 

The function enforces a global, single-call-per-block invariant via `last_reward_block`: [2](#0-1) 

Critically, `last_reward_block` is written **before** the `disable_rewards` branch is evaluated: [3](#0-2) 

`last_reward_block` is a single global storage slot shared across all stakers: [4](#0-3) 

The consequence is that once any caller invokes `update_rewards(any_valid_staker, disable_rewards: true)` at block N, `last_reward_block` is set to N. Every subsequent call to `update_rewards` at block N — including the legitimate consensus call — will revert with `REWARDS_ALREADY_UPDATED`. No staker receives consensus block rewards for block N.

The analog to the multi-sig report is direct: just as a minority of owners could withhold confirmations to force a recovery-mode state transition that benefited them, here a single unprivileged address can force a state transition (`last_reward_block` advance) that permanently discards the reward distribution for that block. The attacker does not need to be a staker, delegator, or hold any privileged role.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

Consensus block rewards are computed once per block per staker via `_update_rewards`. If the per-block slot is consumed with `disable_rewards: true`, the rewards for that block are never credited to `staker_info.unclaimed_rewards_own` and never forwarded to delegation pools. The `RewardSupplier` is never notified, so the tokens remain unaccounted for. The loss is permanent — there is no catch-up mechanism. [5](#0-4) 

An attacker who calls this at the first transaction of every block can freeze 100% of consensus rewards for all stakers indefinitely, at the cost of one cheap transaction per block.

---

### Likelihood Explanation

**High.** The function is publicly callable with no role restriction. The attacker needs only a non-zero address and a valid (active, non-zero-balance) staker address to pass the staker existence checks. Both are trivially obtainable from on-chain data. The gas cost of one call per block on Starknet is negligible relative to the value of rewards frozen. [6](#0-5) 

---

### Recommendation

Restrict `update_rewards` to a trusted caller (e.g., the attestation contract, a designated consensus reporter role, or the staker's own operational address). Alternatively, separate the `disable_rewards` path into a privileged function so that only the protocol can suppress reward distribution, while the reward-granting path remains callable by the staker or their operational address.

---

### Proof of Concept

1. Attacker (any non-zero EOA) observes a new block N is produced.
2. Attacker calls `staking.update_rewards(valid_staker_address, disable_rewards: true)`.
3. Inside the function: `current_block_number (N) > last_reward_block` passes; `last_reward_block` is written to N; the `disable_rewards` branch returns early — no rewards distributed.
4. The legitimate consensus call `update_rewards(staker, false)` at block N reverts: `current_block_number (N) > last_reward_block (N)` is false → `REWARDS_ALREADY_UPDATED`.
5. All stakers lose consensus block rewards for block N.
6. Attacker repeats at block N+1, N+2, … to freeze all future consensus rewards. [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1393-1400)
```text
    impl StakingAttestationImpl of IStakingAttestation<ContractState> {
        fn update_rewards_from_attestation_contract(
            ref self: ContractState, staker_address: ContractAddress,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(self.is_pre_consensus(), "{}", Error::CONSENSUS_REWARDS_IS_ACTIVE);
            self.assert_caller_is_attestation_contract();
```

**File:** src/staking/staking.cairo (L1448-1460)
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
```

**File:** src/staking/staking.cairo (L1484-1507)
```text
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
