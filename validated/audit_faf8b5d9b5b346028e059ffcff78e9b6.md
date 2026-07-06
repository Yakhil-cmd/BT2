### Title
Unbounded `stakers` Vec Causes `get_stakers` to Become Permanently Unusable - (File: src/staking/staking.cairo)

### Summary
The `stakers` storage `Vec` grows monotonically because stakers are never removed from it upon unstaking. The `get_stakers` function in `IStakingConsensus` iterates over the entire vector on every call. Any unprivileged user can extend this vector by staking with the minimum amount and later unstaking, leaving a permanent dead entry. Over time, `get_stakers` will exceed Starknet's execution step limit and become permanently uncallable, breaking the consensus layer's ability to query the active staker set.

### Finding Description

The `stakers` storage vector is declared with an explicit design note that entries are never removed: [1](#0-0) 

Every call to `stake()` unconditionally appends the caller's address: [2](#0-1) 

`unstake_action` never removes the address from `stakers`: [3](#0-2) 

`get_stakers` iterates over the **full range** of this ever-growing vector on every invocation: [4](#0-3) 

Each iteration performs multiple storage reads (`is_staker_active`, `get_staker_staking_power_at_epoch`, `get_public_key_at_epoch`, `get_peer_id_at_epoch`), making the per-entry cost non-trivial.

By contrast, the `btc_tokens` iterable map — which is also iterated in `get_active_tokens` and `get_tokens` — is explicitly bounded by governance policy documented in the interface: [5](#0-4) 

No equivalent bound or comment exists for the `stakers` Vec.

### Impact Explanation

`get_stakers` is the primary entrypoint for the consensus layer to obtain the active staker set for a given epoch. Once the vector grows large enough to exceed Starknet's per-transaction execution step limit, every call to `get_stakers` will revert. This permanently prevents the consensus mechanism from querying staking power, constituting **unbounded gas consumption** leading to a permanent freeze of a critical protocol function.

### Likelihood Explanation

Every unique address that has ever staked contributes one permanent entry. An unprivileged attacker can accelerate growth by deploying many EOA/contract addresses, each staking the minimum amount, waiting out the exit window, and unstaking. The minimum stake requirement raises the cost but does not prevent the attack. Even without a deliberate attacker, organic protocol growth will eventually push the vector past the execution limit.

### Recommendation

1. **Remove stakers on `unstake_action`**: Replace the append-only `Vec` with a data structure that supports deletion (e.g., a swap-and-pop pattern or an `IterableMap` keyed by staker address).
2. **Alternatively, add a hard cap** on the number of registered stakers and document it, analogous to the token set bound in `IStakingTokenManager`.
3. **Paginate `get_stakers`**: Accept `offset` and `limit` parameters so callers can retrieve the staker list in bounded chunks.

### Proof of Concept

1. Deploy N accounts, each with `min_stake` STRK approved to the staking contract.
2. Each account calls `stake(reward_addr, operational_addr, min_stake)` — each call appends one entry to `self.stakers`.
3. Each account calls `unstake_intent()` then, after the exit window, `unstake_action()` — the entry remains in `self.stakers`.
4. Call `get_stakers(epoch_id)`. As N grows, the execution step count grows linearly. Beyond the Starknet step limit, the call reverts unconditionally, permanently breaking the consensus query interface.

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

**File:** src/staking/staking.cairo (L918-936)
```text
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
```

**File:** src/staking/interface.cairo (L262-270)
```text
pub trait IStakingTokenManager<TContractState> {
    /// Add a new token to the staking contract.
    ///
    /// **Important notes:**
    /// 1. This function should be called only a limited number of times.
    /// Adding too many tokens can lead to unbounded complexity and potential performance issues.
    /// The token set is intended to remain fixed and small, ensuring all loops over it are safely
    /// bounded.
    /// It is the token admin's responsibility to enforce this token limit.
```
