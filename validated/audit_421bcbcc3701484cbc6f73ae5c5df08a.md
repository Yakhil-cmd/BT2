### Title
Unbounded Iteration Over Permanently Growing `stakers` Vec in `get_stakers` Causes Unbounded Gas Consumption — (File: `src/staking/staking.cairo`)

---

### Summary

The `get_stakers` function in `staking.cairo` iterates over a `Vec<ContractAddress>` (`self.stakers`) that grows monotonically with every `stake()` call and is **never pruned** when stakers unstake. Because any unprivileged address can call `stake()` to append to this Vec, the iteration cost of `get_stakers` is unbounded and will eventually exceed gas limits, breaking the consensus mechanism's ability to retrieve the active staker set.

---

### Finding Description

Every call to `stake()` appends the new staker's address to `self.stakers`: [1](#0-0) 

The storage declaration explicitly documents that entries are never removed: [2](#0-1) 

`get_stakers` then iterates over the **entire** Vec unconditionally, performing multiple storage reads per entry (active check, staking power calculation, public key, peer ID): [3](#0-2) 

There is no cap on the number of stakers, no pagination, and no mechanism to remove departed stakers from the Vec. As the protocol accumulates stakers over time — each one permanently occupying a slot — the gas cost of `get_stakers` grows linearly and without bound.

---

### Impact Explanation

`get_stakers` is the primary entrypoint for the consensus layer to retrieve the active validator set for a given epoch. When the Vec grows large enough that a single call exhausts the Starknet transaction gas limit, the consensus mechanism can no longer obtain the staker set. This constitutes **unbounded gas consumption** that degrades and ultimately breaks a core protocol function.

**Allowed impact matched:** Medium — Unbounded gas consumption / griefing with damage to the protocol.

---

### Likelihood Explanation

The `stake()` function is permissionless. Any address meeting the `min_stake` threshold can call it and permanently add an entry to `self.stakers`. Stakers who later call `unstake_action` are removed from `staker_info` but their address remains in the Vec forever. Over the natural lifetime of the protocol, the Vec will grow to a size that makes `get_stakers` uncallable. No adversarial intent is required — organic protocol growth is sufficient.

---

### Recommendation

Replace the full-Vec scan with a paginated view (accept `offset` and `limit` parameters), or maintain a separate active-staker set that removes entries on `unstake_action`. A pull-pattern equivalent here is to let the consensus layer query individual stakers by address rather than scanning the entire registry in one call.

---

### Proof of Concept

1. Deploy the staking contract.
2. Have `N` addresses each call `stake()` with the minimum stake, appending `N` entries to `self.stakers`.
3. Have each of those stakers call `unstake_intent()` then `unstake_action()` — their `staker_info` entries are deleted, but `self.stakers` still holds all `N` addresses.
4. Call `get_stakers(epoch_id)`. The function iterates all `N` slots, reading storage for each. At sufficiently large `N`, the call reverts with an out-of-gas error.
5. The consensus mechanism can no longer retrieve the staker set for any epoch. [4](#0-3) [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L167-169)
```text
        /// Vector of staker addresses.
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
```

**File:** src/staking/staking.cairo (L286-349)
```text
    #[abi(embed_v0)]
    impl StakingImpl of IStaking<ContractState> {
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
