### Title
Unprivileged Caller Can Permanently Freeze All Staker Block Rewards via `update_rewards(disable_rewards: true)` — (File: `src/staking/staking.cairo`)

---

### Summary

The `update_rewards` function in `StakingRewardsManagerImpl` accepts a caller-supplied `disable_rewards: bool` parameter with no authorization check. The function unconditionally advances the **global** `last_reward_block` to the current block number *before* inspecting `disable_rewards`. Any unprivileged caller can invoke `update_rewards(any_valid_staker, disable_rewards: true)` once per block to consume the per-block reward slot while skipping all reward distribution, permanently denying every staker their consensus block rewards.

---

### Finding Description

`update_rewards` is gated only by `general_prerequisites()`, which checks that the contract is unpaused and the caller is non-zero — no role or identity check is performed. [1](#0-0) 

The execution sequence is:

1. Read `current_block_number`.
2. Assert `current_block_number > last_reward_block` (global, single value for all stakers).
3. Validate the supplied `staker_address` is active.
4. **Unconditionally write `last_reward_block = current_block_number`.**
5. If `disable_rewards == true`, return early — no rewards distributed. [2](#0-1) 

`last_reward_block` is a single global storage slot shared across all stakers: [3](#0-2) 

Because the write to `last_reward_block` occurs **before** the `disable_rewards` branch, any caller who supplies `disable_rewards: true` consumes the block's reward slot for the entire protocol. All subsequent calls to `update_rewards` in the same block revert with `REWARDS_ALREADY_UPDATED`: [4](#0-3) 

The analog to `ValidateVoteExtensions` is direct: just as the Cosmos function trusted proposer-injected `totalVP` data without independent verification, `update_rewards` trusts the caller-supplied `disable_rewards` flag to govern whether accounting state (`last_reward_block`) should be advanced — but advances it unconditionally regardless of the flag's value, allowing any caller to manipulate the global accounting state.

---

### Impact Explanation

**High — Permanent freezing of unclaimed yield.**

All stakers in the consensus rewards phase (after `consensus_rewards_first_epoch`) are denied block rewards indefinitely. The attacker calls `update_rewards(any_active_staker, disable_rewards: true)` once per block. Each call:

- Advances `last_reward_block` to the current block.
- Distributes zero rewards.
- Blocks every legitimate reward claim for that block.

Stakers accumulate zero `unclaimed_rewards_own` and pool contracts receive zero `pool_rewards`, permanently freezing yield for the entire protocol. [5](#0-4) 

---

### Likelihood Explanation

**High.** The attack requires:

- A valid, active `staker_address` (trivially observable from on-chain events such as `NewStaker`).
- One transaction per block.
- No privileged access, no leaked keys, no external dependencies.

Starknet transaction fees are low, making sustained per-block griefing economically feasible for any motivated attacker.

---

### Recommendation

Two complementary fixes:

1. **Move `last_reward_block.write` after the `disable_rewards` guard**, so a call with `disable_rewards: true` does not consume the block's reward slot:

```cairo
if disable_rewards || self.is_pre_consensus() {
    return;
}
self.last_reward_block.write(current_block_number); // moved here
```

2. **Add caller authorization** — restrict `update_rewards` to the staker themselves, their reward address, or a designated protocol role (e.g., the attestation contract), consistent with how `update_rewards_from_attestation_contract` is protected: [6](#0-5) 

---

### Proof of Concept

1. Attacker observes any active staker address `S` from on-chain `NewStaker` events.
2. At the start of each new Starknet block, attacker calls:
   ```
   staking.update_rewards(staker_address: S, disable_rewards: true)
   ```
3. `last_reward_block` is set to the current block number; no rewards are distributed.
4. Any legitimate call to `update_rewards` in the same block reverts with `REWARDS_ALREADY_UPDATED`.
5. Attacker repeats step 2 every block.
6. All stakers accumulate zero block rewards indefinitely; `unclaimed_rewards_own` is never incremented; pool members receive no yield.

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

**File:** src/staking/staking.cairo (L1448-1458)
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
```

**File:** src/staking/staking.cairo (L1483-1507)
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
