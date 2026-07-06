### Title
Unbounded `stakers` Vec Growth Enables Griefing of Consensus Validator-Set Query — (`File: src/staking/staking.cairo`)

### Summary
The `stakers` storage Vec in the Staking contract is append-only: every new staker is pushed in, but no entry is ever removed when a staker exits. The `get_stakers` function, which the consensus layer calls to build the validator set, iterates over the **entire** Vec on every invocation. An unprivileged attacker can cheaply inflate the Vec with dead entries by repeatedly staking the minimum amount and then fully unstaking, causing `get_stakers` to consume unbounded execution resources and eventually fail.

### Finding Description
`src/staking/staking.cairo` line 169 declares the Vec:

```cairo
/// Vector of staker addresses.
/// **Note**: Stakers are not removed from this vector when they unstake.
stakers: Vec<ContractAddress>,
``` [1](#0-0) 

Every call to `stake` appends unconditionally:

```cairo
self.stakers.push(staker_address);
``` [2](#0-1) 

`unstake_action` deletes the staker's `staker_info` record and clears pool state, but **never removes the address from `stakers`**: [3](#0-2) 

`get_stakers` (the consensus validator-set query) iterates the full Vec with no upper bound:

```cairo
for staker_address_ptr in self.stakers.into_iter_full_range() {
    let staker_address = staker_address_ptr.read();
    if !self.is_staker_active(:staker_address, :epoch_id) {
        continue;
    }
    ...
}
``` [4](#0-3) 

`is_staker_active` returns `false` for exited stakers, so dead entries are skipped logically, but each one still costs a storage read and a branch — the execution cost scales linearly with the total number of addresses ever staked, not with the number of currently active stakers.

### Impact Explanation
`get_stakers` is the sole mechanism by which the consensus layer discovers the current validator set. If the Vec is inflated to a size that causes the function to exceed Starknet's per-call execution-step limit, the consensus layer can no longer retrieve the validator set. This maps to **Medium: griefing with no profit motive but damage to users or protocol** (unbounded gas/execution consumption). In the worst case, if the consensus layer cannot obtain the validator set, block production stalls, escalating toward **temporary freezing of funds**.

### Likelihood Explanation
The attack is cheap in capital terms: the attacker stakes `min_stake` STRK per account, waits through the `exit_wait_window` (default one week), and calls `unstake_action` to recover the full principal. The only unrecoverable cost is transaction gas. Because `assert_staker_address_not_reused` prevents address reuse, the attacker needs distinct addresses, but Starknet account deployment is inexpensive. A sustained campaign over multiple weeks can grow the Vec to tens of thousands of dead entries with modest total gas spend. [5](#0-4) 

### Recommendation
- **Short term**: Add a `staker_count` counter and a separate `active_stakers` mapping so `get_stakers` can skip dead slots without reading them, or maintain a compact active-staker set that is pruned on `unstake_action`.
- **Long term**: Replace the append-only `Vec` with a data structure that supports O(1) removal (e.g., a swap-and-pop pattern or an `IterableMap` analogous to `btc_tokens`), ensuring the iterable set size is bounded by the number of *currently active* stakers.

### Proof of Concept
1. Attacker deploys N distinct Starknet accounts (A₁ … Aₙ).
2. Each Aᵢ calls `stake(reward_address, operational_address, min_stake)` — `stakers` Vec grows by N.
3. Each Aᵢ calls `unstake_intent()` — sets `unstake_time`.
4. After `exit_wait_window` elapses, each Aᵢ calls `unstake_action(Aᵢ)` — principal is returned; `staker_info` is cleared; **`stakers` Vec is not trimmed**.
5. Any subsequent call to `get_stakers(epoch_id)` must iterate all N dead entries plus the live stakers. As N grows, execution steps grow linearly until the call exceeds the Starknet execution-step cap and reverts, denying the consensus layer its validator set.

### Citations

**File:** src/staking/staking.cairo (L167-170)
```text
        /// Vector of staker addresses.
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
        /// Map token address to its decimals.
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
