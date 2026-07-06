### Title
Append-Only `stakers` Vec Enables Unbounded Gas Consumption in `get_stakers()` - (File: src/staking/staking.cairo)

### Summary
The `stakers: Vec<ContractAddress>` storage field in the Staking contract is append-only by explicit design. Stakers are never removed from this Vec when they unstake. The `get_stakers()` function iterates over the **full range** of this Vec on every call. An unprivileged attacker can bloat this Vec by repeatedly staking and unstaking with minimum-stake accounts, causing `get_stakers()` to consume unbounded gas.

### Finding Description

The storage declaration at line 168–169 of `src/staking/staking.cairo` explicitly documents the issue:

```cairo
/// **Note**: Stakers are not removed from this vector when they unstake.
stakers: Vec<ContractAddress>,
``` [1](#0-0) 

The `get_stakers()` function, part of `IStakingConsensus`, iterates over the entire Vec using `into_iter_full_range()`:

```cairo
for staker_address_ptr in self.stakers.into_iter_full_range() {
    let staker_address = staker_address_ptr.read();
    if !self.is_staker_active(:staker_address, :epoch_id) {
        continue;
    }
    ...
}
``` [2](#0-1) 

Every inactive (unstaked) address still occupies a slot in the Vec and is read from storage on each call. There is no mechanism to compact or prune the Vec.

### Impact Explanation

`get_stakers()` is a consensus-critical function that returns the active validator set for a given epoch. As the `stakers` Vec grows with each unique staker address ever registered, the gas cost of iterating the full range grows linearly and without bound. If this function is invoked on-chain (e.g., by the attestation contract or a future consensus contract), a sufficiently bloated Vec will cause the call to revert with an out-of-gas error, breaking the validator-set query and potentially stalling reward distribution or attestation.

**Impact class**: Medium — Unbounded gas consumption / griefing with damage to protocol.

### Likelihood Explanation

Any unprivileged address can call `stake()` with the minimum stake amount, then call `unstake_intent()` and `unstake_action()` after the `exit_wait_window`. Each such round-trip permanently adds one entry to the `stakers` Vec. The attacker recovers their principal after the exit window, so the only sustained cost is transaction fees. With a low `min_stake`, this attack is economically feasible at scale.

### Recommendation

1. **Swap-and-pop on unstake**: When a staker fully exits (in `remove_staker`), swap their entry in `stakers` with the last element and decrement the Vec length. This keeps the Vec compact.
2. **Alternatively**, maintain a separate active-staker count and enforce an upper bound on the Vec length, or use a different data structure (e.g., an `IterableMap` that supports deletion) instead of a plain `Vec`. [3](#0-2) 

### Proof of Concept

1. Deploy the staking contract with `min_stake = M`.
2. For `i = 1..N`, create a fresh account `A_i`, fund it with `M` STRK, and call `stake()`. Each call appends `A_i` to `stakers`.
3. After `exit_wait_window` passes, call `unstake_intent()` then `unstake_action()` for each `A_i`. The staker info is cleared, but `stakers[i]` still holds `A_i`.
4. Call `get_stakers(epoch_id)`. The function reads all `N` entries from storage, checks `is_staker_active` for each, and skips all of them. Gas consumed ∝ N.
5. Repeat until `get_stakers()` exceeds the block gas limit, making the validator-set query permanently unusable on-chain. [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L167-169)
```text
        /// Vector of staker addresses.
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
```

**File:** src/staking/staking.cairo (L901-937)
```text
        fn get_stakers(
            self: @ContractState, epoch_id: Epoch,
        ) -> Span<(ContractAddress, StakingPower, Option<PublicKey>, Option<PeerId>)> {
            let curr_epoch = self.get_current_epoch();
            assert!(
                curr_epoch <= epoch_id && epoch_id < curr_epoch + K.into(),
                "{}",
                Error::INVALID_EPOCH,
            );

            let (strk_total_stake, btc_total_stake) = self
                .get_total_staking_power_at_epoch(:epoch_id);

            let mut stakers: Array<
                (ContractAddress, StakingPower, Option<PublicKey>, Option<PeerId>),
            > =
                array![];
            for staker_address_ptr in self.stakers.into_iter_full_range() {
                let staker_address = staker_address_ptr.read();
                if !self.is_staker_active(:staker_address, :epoch_id) {
                    continue;
                }

                let staking_power = self
                    .get_staker_staking_power_at_epoch(
                        :staker_address, :epoch_id, :strk_total_stake, :btc_total_stake,
                    );
                if staking_power.is_zero() {
                    continue;
                }

                let public_key = self.get_public_key_at_epoch(:staker_address, :epoch_id);
                let peer_id = self.get_peer_id_at_epoch(:staker_address, :epoch_id);
                stakers.append((staker_address, staking_power, public_key, peer_id));
            }
            stakers.span()
        }
```

**File:** src/staking/staking.cairo (L1686-1708)
```text
        fn remove_staker(
            ref self: ContractState,
            staker_address: ContractAddress,
            staker_info: InternalStakerInfoLatest,
            staker_pool_info: StoragePath<Mutable<InternalStakerPoolInfoV2>>,
        ) {
            self.insert_staker_own_balance(:staker_address, own_balance: Zero::zero());
            self.staker_info.write(staker_address, VInternalStakerInfo::None);
            let operational_address = staker_info.operational_address;
            self.operational_address_to_staker_address.write(operational_address, Zero::zero());
            staker_pool_info.commission.write(Option::None);
            staker_pool_info.commission_commitment.write(Option::None);
            let pool_contracts = staker_pool_info.get_pools();
            self
                .emit(
                    Events::DeleteStaker {
                        staker_address,
                        reward_address: staker_info.reward_address,
                        operational_address,
                        pool_contracts,
                    },
                );
        }
```
