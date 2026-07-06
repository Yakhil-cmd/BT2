### Title
Unbounded `stakers` Vec Growth Causes `get_stakers` Gas Exhaustion - (File: src/staking/staking.cairo)

### Summary
The `stakers` storage vector in the Staking contract grows indefinitely because staker addresses are appended on every `stake()` call but are **never removed** when a staker calls `unstake_action()`. The `get_stakers` function iterates over the entire vector on every invocation. An unprivileged attacker can bloat this vector by cycling through many addresses (each staking the minimum amount, then unstaking), making `get_stakers` prohibitively expensive or impossible to execute, disrupting the consensus layer's ability to determine voting power.

### Finding Description
In `src/staking/staking.cairo`, the `stake()` function unconditionally appends the caller's address to the `stakers` Vec:

```cairo
// Add staker address to the stakers vector.
self.stakers.push(staker_address);
```

The storage declaration itself documents this design:

```cairo
/// Vector of staker addresses.
/// **Note**: Stakers are not removed from this vector when they unstake.
stakers: Vec<ContractAddress>,
```

The `unstake_action()` function removes the staker's `InternalStakerInfo` record and transfers funds back, but never pops or tombstones the entry in `stakers`.

The `get_stakers()` function then iterates over the **full range** of this ever-growing vector:

```cairo
for staker_address_ptr in self.stakers.into_iter_full_range() {
    let staker_address = staker_address_ptr.read();
    if !self.is_staker_active(:staker_address, :epoch_id) {
        continue;
    }
    ...
}
```

Every historical staker address — including those who have long since unstaked — is read from storage on every call. The `is_staker_active` check skips inactive stakers, but the storage reads still occur for every entry.

The `assert_staker_address_not_reused` guard in `stake()` prevents address reuse, so each attack iteration requires a fresh address. However, the attacker recovers their principal after the `exit_wait_window` (default one week, max twelve weeks), making the attack capital-efficient over time.

### Impact Explanation
`get_stakers` is the function the consensus layer uses to enumerate all active stakers and their voting power for a given epoch. As the `stakers` Vec grows, the per-call cost of `get_stakers` grows linearly. Once the vector is large enough, the call exceeds Starknet's execution resource limits, permanently preventing the consensus layer from reading staker data. This constitutes **unbounded gas consumption** (Medium) and, if the consensus layer cannot function, can escalate to **temporary freezing of unclaimed yield** for all stakers who cannot attest and earn rewards.

### Likelihood Explanation
The attack requires the adversary to stake with many distinct addresses, each holding at least `min_stake` STRK. Funds are returned after the exit window, so the sustained cost is only the opportunity cost of locked capital plus transaction fees. With a sufficiently low `min_stake` or a well-funded attacker, the vector can be bloated to thousands of entries across multiple exit-window cycles. The attack is permissionless and requires no privileged access.

### Recommendation
1. **Short term**: Document the known growth of `stakers` and the resulting `get_stakers` cost so integrators and the consensus layer can plan for pagination or off-chain enumeration.
2. **Long term**: Replace the append-only `stakers: Vec` with a structure that supports removal (e.g., a swap-and-pop pattern or a separate active-staker count), or add a pagination parameter to `get_stakers` so callers can bound the work per transaction. Alternatively, maintain a separate `active_stakers` set that is updated on `unstake_action`.

### Proof of Concept
1. Attacker controls addresses `A_1 … A_N`, each funded with `min_stake` STRK.
2. For each `A_i`: call `stake(reward_address, operational_address, min_stake)` → `A_i` is appended to `stakers`.
3. For each `A_i`: call `unstake_intent()`, wait `exit_wait_window`, call `unstake_action(A_i)` → funds returned, but `A_i` remains in `stakers`.
4. Repeat with fresh addresses using recovered funds.
5. After enough iterations, `get_stakers(epoch_id)` iterates over `N` entries, each requiring a storage read, exceeding execution limits and reverting.
6. The consensus layer can no longer enumerate active stakers; stakers cannot attest and earn rewards.

**Relevant code locations:** [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L168-170)
```text
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
        /// Map token address to its decimals.
```

**File:** src/staking/staking.cairo (L346-349)
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
