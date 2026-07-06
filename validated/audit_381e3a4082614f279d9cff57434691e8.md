### Title
Unprivileged Caller Can Permanently Freeze Block Rewards via `update_rewards(disable_rewards: true)` - (File: src/staking/staking.cairo)

### Summary
The `IStakingRewardsManager::update_rewards` function in the Staking contract lacks access control, while the analogous pre-consensus function `update_rewards_from_attestation_contract` is strictly gated to the attestation contract. Any unprivileged caller can invoke `update_rewards` with `disable_rewards: true`, which advances the global `last_reward_block` counter without distributing any rewards. Because the function enforces a one-call-per-block invariant on that global counter, the legitimate reward distribution for that block is permanently lost.

### Finding Description

**Inconsistency between the two reward-update paths:**

The pre-consensus reward path `update_rewards_from_attestation_contract` enforces `assert_caller_is_attestation_contract()`: [1](#0-0) 

The consensus reward path `update_rewards` applies only `general_prerequisites()` — which checks "not paused" and "caller ≠ zero address" — with no role restriction: [2](#0-1) 

`general_prerequisites` itself: [3](#0-2) 

**The global `last_reward_block` one-call-per-block gate:** [4](#0-3) 

**The early-return when `disable_rewards` is true, after the counter is already advanced:** [5](#0-4) 

The sequence is:
1. `last_reward_block` is written to the current block number (line 1485).
2. If `disable_rewards || is_pre_consensus()` → return immediately, no rewards distributed.
3. Any subsequent call in the same block hits `REWARDS_ALREADY_UPDATED` and reverts.

Because `last_reward_block` is a single global slot shared across all stakers, consuming it with `disable_rewards: true` for *any* valid staker blocks reward distribution for *every* staker in that block.

### Impact Explanation

An attacker who calls `update_rewards(any_active_staker, disable_rewards: true)` once per block permanently destroys that block's worth of unclaimed yield for all stakers. Repeated every block, this freezes the entire consensus-phase reward stream. This matches **High: Permanent freezing of unclaimed yield**.

### Likelihood Explanation

- No privileged role is required; any non-zero address suffices.
- Active staker addresses are publicly visible on-chain.
- The attacker simply needs to submit the griefing transaction before the legitimate caller in each block (straightforward front-running or independent submission).
- The cost is only gas; there is no capital requirement.

### Recommendation

Gate `update_rewards` with the same attestation-contract check used by `update_rewards_from_attestation_contract`:

```cairo
fn update_rewards(
    ref self: ContractState, staker_address: ContractAddress, disable_rewards: bool,
) {
    self.general_prerequisites();
+   self.assert_caller_is_attestation_contract(); // mirror pre-consensus path
    ...
}
``` [6](#0-5) 

### Proof of Concept

```
Block N:
  Attacker tx:  staking.update_rewards(alice_staker, disable_rewards=true)
    → last_reward_block := N
    → returns early, zero rewards distributed

  Legitimate tx (attestation contract or staker): staking.update_rewards(alice_staker, disable_rewards=false)
    → assert!(N > N)  ← FAILS with REWARDS_ALREADY_UPDATED

Block N+1: attacker repeats → all block rewards permanently frozen.
```

### Citations

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
