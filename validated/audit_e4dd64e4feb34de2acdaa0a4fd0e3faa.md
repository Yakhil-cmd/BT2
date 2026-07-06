### Title
Missing Caller Restriction in `update_rewards` Allows Any Caller to Permanently Deny Block Rewards for All Stakers - (File: src/staking/staking.cairo)

### Summary
The `update_rewards` function in the Staking contract has no caller restriction, while the analogous `update_rewards_from_attestation_contract` function enforces `assert_caller_is_attestation_contract()`. Because `last_reward_block` is a **global** storage variable and the contract enforces exactly one reward update per block, any unprivileged caller can invoke `update_rewards(valid_staker, disable_rewards: true)` to consume the per-block reward slot without distributing any rewards, permanently denying all stakers their consensus block rewards for that block.

### Finding Description
The asymmetry is direct:

`update_rewards_from_attestation_contract` (pre-consensus path): [1](#0-0) 

enforces two guards — `is_pre_consensus()` and `assert_caller_is_attestation_contract()`: [2](#0-1) 

`update_rewards` (consensus path): [3](#0-2) 

has **no caller restriction** — only `general_prerequisites()` (not paused, caller non-zero): [4](#0-3) 

The global `last_reward_block` is written unconditionally before the `disable_rewards` branch: [5](#0-4) 

After writing `last_reward_block`, the function returns early if `disable_rewards` is true, distributing nothing: [6](#0-5) 

Any subsequent call in the same block — including the legitimate consensus-layer call — fails with `REWARDS_ALREADY_UPDATED`: [7](#0-6) 

### Impact Explanation
`last_reward_block` is a single global field shared across all stakers: [8](#0-7) 

One attacker call per block with `disable_rewards: true` permanently voids the block reward for every staker for that block. The rewards are not deferred — they are simply never calculated or credited. This constitutes **permanent freezing / theft of unclaimed yield** (High impact under the allowed scope).

### Likelihood Explanation
The entry path requires no privilege: any non-zero address can call `update_rewards` on any active staker with `disable_rewards: true`. The attacker only needs to submit a transaction in the same block before the legitimate consensus-layer call. In Starknet's sequencer model, transaction ordering is controlled by the sequencer, but the function is fully public and callable by any EOA or contract. The only cost is gas per block.

### Recommendation
Add a caller restriction to `update_rewards` analogous to `assert_caller_is_attestation_contract()` used in `update_rewards_from_attestation_contract`. Introduce a stored `consensus_contract` address and assert `get_caller_address() == self.consensus_contract.read()` at the top of `update_rewards`, mirroring the pattern at: [9](#0-8) 

### Proof of Concept
1. Consensus rewards are active (`consensus_rewards_first_epoch` is set and current epoch ≥ it).
2. A valid staker `S` exists with non-zero STRK balance.
3. Attacker submits `staking.update_rewards(S, disable_rewards: true)` in block `B`.
4. `last_reward_block` is written to `B`; no rewards are distributed.
5. The legitimate consensus-layer call `staking.update_rewards(block_proposer, disable_rewards: false)` in the same block `B` panics with `REWARDS_ALREADY_UPDATED`.
6. The block proposer's (and all stakers') rewards for block `B` are permanently lost.
7. Repeat every block to continuously deny all consensus rewards.

### Citations

**File:** src/staking/staking.cairo (L187-188)
```text
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1393-1402)
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
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
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
