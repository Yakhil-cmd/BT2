### Title
Unbounded `stakers` Vec Iteration in `get_stakers` Causes Unbounded Gas Consumption - (File: src/staking/staking.cairo)

### Summary
The `stakers` storage `Vec<ContractAddress>` in the `Staking` contract grows monotonically — every call to `stake()` appends a new address and stakers are **never removed** even after `unstake_action`. The public `get_stakers` function iterates over the entire vector unconditionally. As the staker set grows organically (or via a capital-funded griefing campaign), the gas cost of `get_stakers` grows without bound, eventually making the function uncallable.

### Finding Description

The `stakers` field is declared as a `Vec<ContractAddress>` with an explicit design note that entries are never removed: [1](#0-0) 

Every successful `stake()` call unconditionally appends the caller's address: [2](#0-1) 

`unstake_action` never removes the staker from this vector — it only deletes the `staker_info` map entry and clears pool data: [3](#0-2) 

`get_stakers`, a public function in `IStakingConsensus`, iterates over the **full range** of this ever-growing vector on every call: [4](#0-3) 

Inside the loop, for each address it reads storage (`is_staker_active`), computes staking power (which itself reads multiple traces), and looks up public key and peer ID — all storage reads that multiply the gas cost per iteration.

A secondary unbounded loop exists in `Pool.calculate_rewards`, which the code itself acknowledges: [5](#0-4) 

### Impact Explanation

`get_stakers` is the canonical on-chain source of truth for the active staker set used by the consensus and attestation layer. As the cumulative count of ever-registered stakers grows, each call to `get_stakers` consumes proportionally more gas. Once the vector is large enough, the function exceeds the Starknet per-transaction gas ceiling and becomes permanently uncallable. This breaks the attestation flow that feeds `update_rewards_from_attestation_contract`, freezing reward distribution for all stakers — matching the **Medium: unbounded gas consumption / griefing** impact class, with potential escalation to **High: permanent freezing of unclaimed yield** if the attestation pipeline depends on on-chain invocation of `get_stakers`.

### Likelihood Explanation

Organic protocol growth alone drives the vector upward with no attacker involvement. Every staker who ever participated — including those who fully exited — permanently occupies a slot. A motivated attacker with sufficient STRK can accelerate this by registering many staker addresses (each meeting `min_stake`), then unstaking, leaving dead entries that still cost gas to iterate. Because the cost is paid by whoever calls `get_stakers` (not the registrant), the attacker bears only the capital cost of the initial stakes, which can be recovered after unstaking.

### Recommendation

1. **Lazy deletion / active-set index**: Maintain a separate compact set of currently-active staker addresses (e.g., an `IterableMap` that supports removal) and iterate only over that set in `get_stakers`.
2. **Pagination**: Add `offset` / `limit` parameters to `get_stakers` so callers can page through results within a single transaction's gas budget.
3. **Cap on staker count**: Enforce a protocol-level maximum on simultaneous active stakers, or require a minimum stake large enough to make mass registration economically infeasible.
4. For `calculate_rewards` in `pool.cairo`: enforce a maximum number of unclaimed balance-change epochs (e.g., require periodic claims or cap the trace length), or paginate reward claims.

### Proof of Concept

1. Deploy the staking contract with `min_stake = M`.
2. Register `N` staker addresses (each funded with `M` STRK), calling `stake()` for each. Each call executes `self.stakers.push(staker_address)`.
3. Call `unstake_intent()` + `unstake_action()` for all `N` stakers. Their `staker_info` entries are deleted, but the `stakers` Vec still holds all `N` addresses.
4. Call `get_stakers(epoch_id)`. The function iterates all `N` slots, reading storage for each. For sufficiently large `N`, the transaction runs out of gas and reverts.
5. All subsequent calls to `get_stakers` — including those from the attestation/consensus layer — will also revert, halting reward distribution. [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L167-169)
```text
        /// Vector of staker addresses.
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
```

**File:** src/staking/staking.cairo (L347-349)
```text
            // Add staker address to the stakers vector.
            self.stakers.push(staker_address);

```

**File:** src/staking/staking.cairo (L483-514)
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

**File:** src/pool/pool.cairo (L857-877)
```text
            // **Note**: The loop iterates over the balance changes in the pool member's balance
            // trace. This loop is unbounded but unlikely to exceed gas limits.
            while entry_to_claim_from < pool_member_trace_length {
                let pool_member_checkpoint = pool_member_trace.at(entry_to_claim_from);
                // If the balance change is after `until_epoch` (and therefore does not affect
                // the current reward computation), exit the loop.
                if pool_member_checkpoint.epoch() >= until_epoch {
                    break;
                }

                // Compute rewards from (inclusive) the previous balance change (or from
                // `from_checkpoint`) to (exclusive) the current entry.
                let to_sigma = self.find_sigma(pool_member_checkpoint, curr_epoch: until_epoch);
                rewards +=
                    compute_rewards_rounded_down(
                        amount: from_balance, interest: to_sigma - from_sigma, :base_value,
                    );
                from_sigma = to_sigma;
                from_balance = pool_member_checkpoint.balance();
                entry_to_claim_from += 1;
            }
```
