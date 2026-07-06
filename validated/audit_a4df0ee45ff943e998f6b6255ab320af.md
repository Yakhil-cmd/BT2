### Title
Unbounded `stakers` Vec Growth Causes Permanent Unbounded Gas Consumption in `get_stakers()` - (File: src/staking/staking.cairo)

### Summary
The `stakers` storage Vec in `staking.cairo` grows with every `stake()` call and entries are **never removed** when stakers unstake. The `get_stakers()` function in `IStakingConsensus` iterates over the entire Vec on every call. An attacker can permanently bloat this Vec by cycling through stake/unstake with many addresses, causing `get_stakers()` to consume unbounded gas and eventually become uncallable.

### Finding Description

Every call to `stake()` unconditionally appends the caller's address to the `stakers` Vec: [1](#0-0) 

The storage declaration explicitly documents that entries are never removed: [2](#0-1) 

The `get_stakers()` function in `IStakingConsensus` iterates over the **full range** of this Vec on every invocation, performing per-staker storage reads and staking power calculations: [3](#0-2) 

The `min_stake` check on `stake()` is the only barrier: [4](#0-3) 

However, this is not a permanent cost — an attacker recovers their principal after the exit wait window via `unstake_intent()` + `unstake_action()`. The `stakers` Vec entries, however, are **permanent and irremovable**.

The `IStakingConsensus.get_stakers()` interface note confirms this function is the consensus layer's primary mechanism for enumerating validator sets: [5](#0-4) 

### Impact Explanation

As the `stakers` Vec grows, `get_stakers()` must iterate over an ever-increasing number of entries, each requiring multiple storage reads (`is_staker_active`, `get_staker_staking_power_at_epoch`, `get_public_key_at_epoch`, `get_peer_id_at_epoch`). Eventually the function exceeds Starknet's gas/step limits for `starknet_call` RPC invocations, making it permanently uncallable. This disrupts the consensus layer's ability to enumerate the validator set, constituting **unbounded gas consumption** and **griefing damage to the protocol**.

**Allowed impact matched**: Medium — Unbounded gas consumption / Griefing with no profit motive but damage to users or protocol.

### Likelihood Explanation

The attack requires capital equal to `N × min_stake` locked for one exit wait window, after which the principal is fully recovered. The only permanent cost is gas for `N` stake/unstake cycles. On Starknet, transaction fees are low, making this economically feasible for a motivated attacker. No privileged role is required — any unprivileged address can call `stake()`.

### Recommendation

1. **Remove stakers from the Vec on `unstake_action()`**, or use a separate active-staker count/set that shrinks when stakers exit.
2. Alternatively, replace the `Vec<ContractAddress>` with an `IterableMap` that supports deletion, analogous to how `btc_tokens` uses `IterableMap`: [6](#0-5) 

3. Add an upper bound on the number of registered stakers, enforced at `stake()` time.

### Proof of Concept

1. Attacker generates N addresses (e.g., N = 10,000).
2. Each address calls `stake(reward_address, operational_address, min_stake)` — each call appends to `stakers` Vec.
3. Each address calls `unstake_intent()` immediately after staking.
4. After the exit wait window, each address calls `unstake_action()` to recover `min_stake` principal.
5. The `stakers` Vec now permanently contains N extra entries.
6. Any subsequent call to `get_stakers(epoch_id)` must iterate all N + existing entries, performing multiple storage reads per entry.
7. Once N is large enough, `get_stakers()` exceeds Starknet's execution step limit and reverts, permanently breaking the consensus layer's validator enumeration.

### Citations

**File:** src/staking/staking.cairo (L166-169)
```text
        btc_tokens: IterableMap<ContractAddress, (Epoch, bool)>,
        /// Vector of staker addresses.
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
```

**File:** src/staking/staking.cairo (L317-317)
```text
            assert!(amount >= self.min_stake.read(), "{}", Error::AMOUNT_LESS_THAN_MIN_STAKE);
```

**File:** src/staking/staking.cairo (L347-349)
```text
            // Add staker address to the stakers vector.
            self.stakers.push(staker_address);

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

**File:** src/staking/interface.cairo (L112-123)
```text
    /// Returns a span of (staker_address, staking_power, Option<public_key>, Option<peer_id>)
    /// for all stakers for the given `epoch_id` (`curr_epoch <= epoch_id < curr_epoch + K`).
    /// **Note**: The staking power is the relative weight of the staker's stake
    /// out of the total stake, including pooled stake (STRK and BTC), multiplied by
    /// `STAKING_POWER_BASE_VALUE`.
    /// **Note**: Disregards stakers that either no staking power, which can be either new stakers
    /// or stakers that called `exit_intent`.
    /// **Note**: Calling this function in the same epoch as the upgrade to V3 may panic.
    /// This will occur if a new staker was added in that epoch before the upgrade.
    fn get_stakers(
        self: @TContractState, epoch_id: Epoch,
    ) -> Span<(ContractAddress, StakingPower, Option<PublicKey>, Option<PeerId>)>;
```
