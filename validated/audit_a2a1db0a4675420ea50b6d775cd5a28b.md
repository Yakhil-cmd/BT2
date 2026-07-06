### Title
Unprivileged Caller Can Pass `disable_rewards=true` to `update_rewards`, Permanently Freezing Staker Yield — (File: src/staking/staking.cairo)

---

### Summary

`IStakingRewardsManager.update_rewards` is a public function with no access control. It accepts a caller-supplied `disable_rewards: bool` parameter. When set to `true`, the function writes the current block number into the global `last_reward_block` storage slot **before** checking the flag, then returns without distributing any rewards. Because `last_reward_block` is a single global variable, any subsequent legitimate call in the same block is rejected with `REWARDS_ALREADY_UPDATED`. An unprivileged caller can exploit this every block to permanently freeze all staker yield.

---

### Finding Description

`update_rewards` is defined in the `IStakingRewardsManager` interface with no role restriction: [1](#0-0) 

The implementation in `staking.cairo` performs only `general_prerequisites()` (unpaused + non-zero caller) before proceeding: [2](#0-1) 

The critical ordering flaw: `last_reward_block` is written **before** the `disable_rewards` branch: [3](#0-2) 

`last_reward_block` is a single global slot shared across all stakers: [4](#0-3) 

Consequence: once any caller invokes `update_rewards(any_valid_staker, disable_rewards: true)` in block N, `last_reward_block` becomes N. Every subsequent call in block N — including the legitimate consensus-mechanism call — fails the guard at line 1454–1458. No staker receives rewards for block N.

The reward distribution that is skipped is the full per-block STRK/BTC reward calculation: [5](#0-4) 

---

### Impact Explanation

By calling `update_rewards(valid_staker, disable_rewards: true)` once per block, an attacker permanently prevents the consensus reward pipeline from crediting any staker. Rewards are never added to `unclaimed_rewards_own` and never forwarded to delegation pools. This constitutes **permanent freezing of unclaimed yield** for every staker and delegator in the protocol.

Impact category matched: **High — Permanent freezing of unclaimed yield.**

---

### Likelihood Explanation

- The function is unconditionally public; no role, signature, or stake is required.
- The attacker only needs to submit one transaction per block with a valid (non-zero-balance) staker address as the argument.
- Gas cost on Starknet L2 is low, making sustained block-by-block griefing economically viable.
- The attacker gains nothing financially, but the damage to every staker and delegator is total loss of consensus-phase yield.

---

### Recommendation

1. **Add access control**: restrict `update_rewards` to a designated rewards-manager role (e.g., the consensus sequencer address or a `REWARDS_MANAGER` role), mirroring how `update_rewards_from_attestation_contract` is restricted to the attestation contract. [6](#0-5) 

2. **Move the `last_reward_block` write**: place `self.last_reward_block.write(current_block_number)` **after** the `disable_rewards` early-return, so a no-op call does not consume the block's reward slot.

---

### Proof of Concept

```
Block N:
  Attacker → staking.update_rewards(staker=Alice, disable_rewards=true)
    → general_prerequisites() passes (not paused, caller ≠ 0)
    → assert(N > last_reward_block)  ✓  (last_reward_block = N-1)
    → last_reward_block.write(N)          ← slot consumed
    → disable_rewards == true → return    ← no rewards distributed

  Consensus mechanism → staking.update_rewards(staker=Alice, disable_rewards=false)
    → assert(N > last_reward_block)  ✗  (N > N is false)
    → REWARDS_ALREADY_UPDATED panic

Block N+1, N+2, … : attacker repeats → all stakers earn zero yield indefinitely.
```

### Citations

**File:** src/staking/interface.cairo (L304-311)
```text
pub trait IStakingRewardsManager<TContractState> {
    /// Update current block rewards for the given `staker_address`.
    /// Distribute rewards only if `disable_rewards` is `false` and consensus rewards already
    /// started.
    fn update_rewards(
        ref self: TContractState, staker_address: ContractAddress, disable_rewards: bool,
    );
}
```

**File:** src/staking/staking.cairo (L186-188)
```text
        /// Last block number for which rewards were distributed.
        last_reward_block: BlockNumber,
        /// First epoch of consensus rewards distribution.
```

**File:** src/staking/staking.cairo (L1392-1401)
```text
    #[abi(embed_v0)]
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

**File:** src/staking/staking.cairo (L1484-1489)
```text
            // Update last block rewards.
            self.last_reward_block.write(current_block_number);

            if disable_rewards || self.is_pre_consensus() {
                return;
            }
```

**File:** src/staking/staking.cairo (L1491-1507)
```text
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
