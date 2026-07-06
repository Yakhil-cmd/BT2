### Title
Permanent Growth of `stakers` Vec Enables Griefing to Render `get_stakers` Unusable - (File: `src/staking/staking.cairo`)

### Summary
The `stakers: Vec<ContractAddress>` storage variable in the Staking contract is append-only — stakers are explicitly never removed from it after unstaking. The consensus-critical `get_stakers()` function iterates over the **entire** vector on every call. An unprivileged attacker can permanently bloat this vector at minimal recurring cost (only `min_stake` STRK locked at any one time) by cycling through fresh addresses: stake → unstake_intent → unstake_action → repeat with new address. Eventually `get_stakers()` exceeds Starknet execution resource limits and becomes permanently uncallable, breaking consensus integration.

### Finding Description

The storage declaration explicitly documents the design flaw:

```
/// Vector of staker addresses.
/// **Note**: Stakers are not removed from this vector when they unstake.
stakers: Vec<ContractAddress>,
``` [1](#0-0) 

Every call to `stake()` unconditionally appends to this vector:

```cairo
// Add staker address to the stakers vector.
self.stakers.push(staker_address);
``` [2](#0-1) 

`get_stakers()` iterates over the **full range** of the vector on every invocation, with no pagination or size bound:

```cairo
for staker_address_ptr in self.stakers.into_iter_full_range() {
    let staker_address = staker_address_ptr.read();
    if !self.is_staker_active(:staker_address, :epoch_id) {
        continue;
    }
    // ... per-staker storage reads ...
}
``` [3](#0-2) 

Although inactive stakers are skipped via `continue`, the loop body still executes a storage read (`staker_address_ptr.read()`) and an `is_staker_active` check for **every** historical entry. As the vector grows, the total execution resources consumed by `get_stakers()` grow linearly and without bound.

The attack cycle is:
1. Attacker calls `stake()` with address `A` and `min_stake` STRK → address `A` is pushed to `stakers`.
2. Attacker calls `unstake_intent()` from address `A`.
3. After `exit_wait_window`, attacker calls `unstake_action()` from address `A` → STRK is returned.
4. Attacker repeats with fresh address `B`, `C`, … recycling the same STRK tokens each time.

`assert_staker_address_not_reused` prevents reusing address `A`, but the attacker simply uses a new address each iteration. The only recurring cost is gas per cycle; the STRK principal is fully recovered after each unstake. [4](#0-3) 

### Impact Explanation

`get_stakers()` is the consensus-layer entrypoint that external systems call to determine the active validator set for a given epoch. Once the `stakers` vector is large enough to exhaust Starknet execution resources, every call to `get_stakers()` reverts. This permanently breaks the consensus integration: the protocol can no longer publish a valid validator set, which constitutes **unbounded gas consumption / griefing with material damage to the protocol** (Medium impact under the allowed scope).

### Likelihood Explanation

The attack requires only `min_stake` STRK (recovered after each cycle) plus gas. There is no privileged role required, no external dependency, and no special knowledge beyond the public ABI. Any unprivileged address can execute this. The cost scales linearly with the number of entries added, making a sustained griefing campaign economically feasible.

### Recommendation

1. **Remove exited stakers from the vector** — swap-and-pop the staker's entry in `stakers` during `unstake_action`, or maintain a separate active-staker count and skip-list.
2. **Alternatively, replace the `Vec` with a paginated or indexed structure** — store only currently-active stakers and remove entries on exit, so `get_stakers()` only iterates over live entries.
3. **Add a hard cap** on the number of registered stakers as a short-term mitigation, though this has its own trade-offs.

### Proof of Concept

```
// Attacker script (pseudocode):
for i in 0..N:
    addr_i = fresh_address(i)
    fund(addr_i, min_stake)
    staking.stake(addr_i, reward=addr_i, operational=fresh_op(i), amount=min_stake)
    staking.unstake_intent()  // called from addr_i
    advance_time(exit_wait_window)
    staking.unstake_action(addr_i)  // STRK returned to addr_i
    transfer(addr_i -> addr_{i+1}, min_stake)  // recycle funds

// After N iterations:
// stakers.len() == N (all historical, all inactive)
// get_stakers(epoch_id) iterates N entries, each requiring storage reads
// At sufficient N, call reverts with out-of-gas
```

The `stakers` vector length after the attack equals `N` (the number of cycles), while the actual active staker count is 0. `get_stakers()` must still traverse all `N` entries. [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L167-169)
```text
        /// Vector of staker addresses.
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
```

**File:** src/staking/staking.cairo (L288-349)
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
            assert!(self.staker_info.read(staker_address).is_none(), "{}", Error::STAKER_EXISTS);
            assert!(
                self.operational_address_to_staker_address.read(operational_address).is_zero(),
                "{}",
                Error::OPERATIONAL_EXISTS,
            );
            self.assert_staker_address_not_reused(:staker_address);
            assert!(
                !self.does_token_exist(token_address: staker_address), "{}", Error::STAKER_IS_TOKEN,
            );
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
            assert!(
                !self.does_token_exist(token_address: operational_address),
                "{}",
                Error::OPERATIONAL_IS_TOKEN,
            );
            assert!(amount >= self.min_stake.read(), "{}", Error::AMOUNT_LESS_THAN_MIN_STAKE);
            let normalized_amount = NormalizedAmountTrait::from_strk_native_amount(:amount);

            // Transfer funds from staker. Sufficient approvals is a pre-condition.
            let staking_contract = get_contract_address();
            let token_dispatcher = strk_token_dispatcher();
            token_dispatcher
                .checked_transfer_from(
                    sender: staker_address, recipient: staking_contract, amount: amount.into(),
                );

            self
                .initialize_staker_own_balance_trace(
                    :staker_address, own_balance: normalized_amount,
                );

            // Create the record for the staker.
            self
                .staker_info
                .write(
                    staker_address,
                    VInternalStakerInfoTrait::new_latest(:reward_address, :operational_address),
                );

            // Update the operational address mapping, which is a 1 to 1 mapping.
            self.operational_address_to_staker_address.write(operational_address, staker_address);

            // Update total stake.
            self.add_to_total_stake(token_address: STRK_TOKEN_ADDRESS, amount: normalized_amount);

            // Add staker address to the stakers vector.
            self.stakers.push(staker_address);

```

**File:** src/staking/staking.cairo (L483-515)
```text
        fn unstake_action(ref self: ContractState, staker_address: ContractAddress) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let unstake_time = staker_info
                .unstake_time
                .expect_with_err(Error::MISSING_UNSTAKE_INTENT);
            assert!(Time::now() >= unstake_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);

            // Send rewards to staker's reward address.
            // It must be part of this function's flow because staker_info is about to be erased.
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            // Update staker info to storage (it will be erased later).
            // This is done here to avoid re-entrancy.
            self.write_staker_info(:staker_address, :staker_info);

            let staker_amount = self.get_own_balance(:staker_address).to_strk_native_amount();
            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            self.remove_staker(:staker_address, :staker_info, :staker_pool_info);

            // Return stake to staker.
            token_dispatcher
                .checked_transfer(recipient: staker_address, amount: staker_amount.into());
            // Return delegated stake to pools and zero their balances.
            self
                .transfer_to_pools_when_unstake(
                    :staker_address, staker_pool_info: staker_pool_info.as_non_mut(),
                );
            // Clear staker pools.
            staker_pool_info.pools.clear();
            staker_amount
        }
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

**File:** src/staking/staking.cairo (L2204-2217)
```text
        fn assert_staker_address_not_reused(self: @ContractState, staker_address: ContractAddress) {
            // Catch stakers that entered in an older version (V0 or V1), and performed
            // `exit_action` in V1.
            assert!(
                self.staker_balance_trace.entry(key: staker_address).is_empty(),
                "{}",
                Error::STAKER_ADDRESS_ALREADY_USED_IN_V1,
            );
            assert!(
                self.staker_own_balance_trace.entry(key: staker_address).is_empty(),
                "{}",
                Error::STAKER_ADDRESS_ALREADY_USED,
            );
        }
```
