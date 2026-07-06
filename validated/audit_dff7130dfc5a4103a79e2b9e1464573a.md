### Title
Unprivileged Caller Can Permanently Freeze Block Rewards for All Stakers via `update_rewards` with `disable_rewards: true` — (File: `src/staking/staking.cairo`)

---

### Summary

`update_rewards` in the `Staking` contract is a public function with no access control. It accepts a `disable_rewards: bool` parameter. When called with `disable_rewards: true`, it still writes the current block number to the global `last_reward_block` storage slot before returning early — permanently consuming the one-call-per-block reward slot without distributing any rewards. Any unprivileged caller can exploit this to freeze block rewards for all stakers indefinitely.

---

### Finding Description

`update_rewards` is exposed via `IStakingRewardsManager` with no role guard — only `general_prerequisites()` is called, which checks that the contract is unpaused and the caller is non-zero. [1](#0-0) 

The function enforces a global one-call-per-block invariant using `last_reward_block`: [2](#0-1) 

Critically, `last_reward_block` is written **before** the `disable_rewards` branch is evaluated: [3](#0-2) 

This means: if any caller invokes `update_rewards(any_active_staker, disable_rewards: true)`, the block's reward slot is consumed and the function returns without distributing rewards. Any subsequent legitimate call in the same block fails with `REWARDS_ALREADY_UPDATED` because `current_block_number > last_reward_block` is now false.

The `general_prerequisites` guard provides no protection: [4](#0-3) 

---

### Impact Explanation

`last_reward_block` is a **global** slot — one write blocks reward distribution for **all** stakers for that block. An attacker who calls `update_rewards(valid_staker, disable_rewards: true)` once per block permanently destroys the block rewards for every staker in the protocol for that block. Repeated across blocks, this freezes all consensus-era block rewards indefinitely. The lost rewards are never recoverable because the per-block slot cannot be reclaimed.

This matches the allowed impact: **Permanent freezing of unclaimed yield**.

---

### Likelihood Explanation

The entry path requires no privilege, no capital, and no special knowledge — only a valid (non-zero-balance) staker address, which is publicly observable on-chain. The attacker pays only gas. On Starknet, transaction ordering within a block is sequencer-controlled, so the attacker can submit the griefing transaction at any time; it only needs to land before the legitimate consensus call in the same block. The attack is cheap, repeatable every block, and requires no coordination.

---

### Recommendation

Add an access-control guard to `update_rewards` so that only the designated consensus/attestation caller (or a whitelisted role) can invoke it. For example, restrict it to the attestation contract address or a dedicated `REWARDS_MANAGER_ROLE`, consistent with how `update_rewards_from_attestation_contract` is guarded: [5](#0-4) 

Alternatively, move the `self.last_reward_block.write(current_block_number)` write to **after** the `disable_rewards` branch so that a no-op call does not consume the block slot.

---

### Proof of Concept

1. Consensus rewards are active (`is_pre_consensus()` returns `false`).
2. Attacker observes any active staker address `S` with non-zero STRK balance (publicly readable from `staker_own_balance_trace`).
3. At block `N`, attacker submits: `update_rewards(S, disable_rewards: true)`.
4. Execution path:
   - `general_prerequisites()` passes (contract unpaused, caller non-zero). [6](#0-5) 
   - `current_block_number (N) > last_reward_block` — passes. [7](#0-6) 
   - Staker balance check passes (S has non-zero balance). [8](#0-7) 
   - `last_reward_block` is written to `N`. [9](#0-8) 
   - `disable_rewards == true` → early return, zero rewards distributed. [10](#0-9) 
5. Any legitimate `update_rewards` call at block `N` now fails: `N > N` is false → `REWARDS_ALREADY_UPDATED`.
6. All stakers permanently lose block rewards for block `N`.
7. Attacker repeats at block `N+1`, `N+2`, … — total consensus reward distribution is frozen.

### Citations

**File:** src/staking/staking.cairo (L1398-1401)
```text
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

**File:** src/staking/staking.cairo (L1480-1482)
```text
            // Staker exists with zero balance for the first K epochs after `stake`, then the stake
            // becomes effective.
            assert!(staker_total_strk_balance.is_non_zero(), "{}", Error::INVALID_STAKER);
```

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
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
