### Title
Missing Pause Check in `staker_migration` Allows Pool Upgrades During Security Pause - (File: src/staking/staking.cairo)

### Summary
The `staker_migration` function in the `Staking` contract is missing the `general_prerequisites()` guard that every other state-changing function calls. This guard enforces the contract-wide pause. As a result, anyone can call `staker_migration` while the staking contract is paused, forcibly upgrading pool contracts to a new implementation even during an active security incident.

### Finding Description
Every state-changing function in `Staking` begins with `self.general_prerequisites()`, which enforces the pause check. Examples include `stake`, `increase_stake`, `claim_rewards`, `unstake_intent`, `unstake_action`, `change_reward_address`, `set_open_for_delegation`, `add_stake_from_pool`, `remove_from_delegation_pool_intent`, `remove_from_delegation_pool_action`, `switch_staking_delegation_pool`, `update_rewards_from_attestation_contract`, and `update_rewards`. [1](#0-0) [2](#0-1) [3](#0-2) 

The `staker_migration` function, however, omits this call entirely: [4](#0-3) 

`staker_migration` is publicly callable by any address for any `staker_address`. It reads `pool_contract_class_hash` and `pool_eic_class_hash` from storage, then calls `add_new_implementation` and `replace_to` on every pool contract belonging to the staker, and finally marks the staker as migrated to `LATEST_STAKER_VERSION`. [5](#0-4) 

### Impact Explanation
The pause mechanism is the protocol's primary emergency circuit breaker. A realistic scenario:

1. Governance sets `pool_contract_class_hash` to a new V3 pool implementation.
2. A vulnerability is discovered in that implementation.
3. The security agent pauses the staking contract to halt all operations.
4. Despite the pause, any external caller invokes `staker_migration(staker_address)` for any or all stakers.
5. Pool contracts are upgraded to the vulnerable implementation while the system is supposed to be frozen.
6. When the staking contract is unpaused, the now-upgraded pool contracts are exploitable, potentially leading to theft of delegator funds or permanent freezing of pool balances.

This matches the **High** impact category: temporary or permanent freezing of delegator funds, or theft of unclaimed yield held in pool contracts.

### Likelihood Explanation
- `staker_migration` is a public, permissionless function — any address can call it for any staker.
- The V2→V3 migration window is the active period; during that window a pause is most likely to be triggered if a bug is found in the new pool class hash.
- No special privileges or leaked keys are required; the attacker only needs to know a staker address (all staker addresses are emitted as `NewStaker` events and stored in the public `stakers` vector). [6](#0-5) 

### Recommendation
Add `self.general_prerequisites()` as the first statement in `staker_migration`, consistent with every other state-changing function:

```cairo
fn staker_migration(ref self: ContractState, staker_address: ContractAddress) {
+   self.general_prerequisites();   // enforce pause check
    // Assert the staker exists.
    self._internal_staker_info(:staker_address);
    ...
}
```

### Proof of Concept
1. Deploy the staking contract and register stakers with V1/V2 pools.
2. Governance sets `pool_contract_class_hash` and `pool_eic_class_hash` to new V3 hashes.
3. Security agent calls `pause()` on the staking contract.
4. Verify `is_paused()` returns `true`; confirm that `stake`, `claim_rewards`, etc. all revert.
5. Call `staker_migration(staker_address)` from any unprivileged address.
6. Observe that the call succeeds: the pool contracts are upgraded to the new class hash and `staker_version` is written to `LATEST_STAKER_VERSION`, all while the contract is paused.
7. The pool contracts now run the new (potentially vulnerable) implementation, bypassing the security pause that was intended to prevent exactly this state change. [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L168-170)
```text
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
        /// Map token address to its decimals.
```

**File:** src/staking/staking.cairo (L288-296)
```text
        fn stake(
            ref self: ContractState,
            reward_address: ContractAddress,
            operational_address: ContractAddress,
            amount: Amount,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_address = get_caller_address();
```

**File:** src/staking/staking.cairo (L411-414)
```text
        fn claim_rewards(ref self: ContractState, staker_address: ContractAddress) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

**File:** src/staking/staking.cairo (L433-436)
```text
        fn unstake_intent(ref self: ContractState) -> Timestamp {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_address = get_caller_address();
```

**File:** src/staking/staking.cairo (L940-999)
```text
    #[abi(embed_v0)]
    impl StakingMigrationImpl of IStakingMigration<ContractState> {
        fn internal_staker_info(
            self: @ContractState, staker_address: ContractAddress,
        ) -> InternalStakerInfoLatest {
            let internal_staker_info = self._internal_staker_info(:staker_address);
            // Assert staker already migrated to V3.
            assert!(
                self.staker_version.read(staker_address).is_latest(),
                "{}",
                Error::STAKER_NOT_MIGRATED,
            );
            internal_staker_info
        }

        // **Note**: When this function is updated, `LATEST_STAKER_VERSION` should also be updated.
        fn staker_migration(ref self: ContractState, staker_address: ContractAddress) {
            // Assert the staker exists.
            self._internal_staker_info(:staker_address);

            // Assert staker already migrated to V2.
            assert!(
                !self.staker_own_balance_trace.entry(staker_address).is_empty(),
                "{}",
                Error::STAKER_NOT_MIGRATED,
            );

            // Assert the staker is not migrated to V3 yet.
            assert!(
                !self.staker_version.read(staker_address).is_latest(),
                "{}",
                Error::STAKER_ALREADY_MIGRATED,
            );

            // Prepare the implementation data.
            let pool_class_hash = self.pool_contract_class_hash.read();
            let pool_eic_class_hash = self.pool_eic_class_hash.read();
            // Sanity checks.
            assert!(pool_class_hash.is_non_zero(), "{}", InternalError::MISSING_CLASS_HASH);
            assert!(pool_eic_class_hash.is_non_zero(), "{}", InternalError::MISSING_CLASS_HASH);
            let eic_data = EICData { eic_hash: pool_eic_class_hash, eic_init_data: [].span() };
            let implementation_data = ImplementationData {
                impl_hash: pool_class_hash, eic_data: Option::Some(eic_data), final: false,
            };

            // Upgrade pools.
            let pools = self.staker_pool_info.entry(staker_address).pools;
            for pool_contract_ptr in pools.keys_iter() {
                let pool_contract = pool_contract_ptr.read();
                let pool_replaceable_dispatcher = IReplaceableDispatcher {
                    contract_address: pool_contract,
                };
                pool_replaceable_dispatcher.add_new_implementation(:implementation_data);
                pool_replaceable_dispatcher.replace_to(:implementation_data);
            }

            // Mark the staker's version.
            self.staker_version.write(staker_address, LATEST_STAKER_VERSION);
        }
    }
```
