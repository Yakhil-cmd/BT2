### Title
Unbounded `stakers` Vec Growth Enables Griefing DOS on `get_stakers` - (File: `src/staking/staking.cairo`)

---

### Summary

The `stakers: Vec<ContractAddress>` storage field in the `Staking` contract grows monotonically and is never pruned. `get_stakers` iterates the entire vector on every call. An unprivileged attacker can inflate this vector by cycling through many addresses (stake → unstake_intent → unstake_action → repeat with a new address), permanently adding dead entries. Over time this makes `get_stakers` exceed the Starknet gas limit, breaking the consensus layer's ability to read the validator set.

---

### Finding Description

The `stakers` Vec is declared with an explicit note that entries are never removed:

```
/// Vector of staker addresses.
/// **Note**: Stakers are not removed from this vector when they unstake.
stakers: Vec<ContractAddress>,
```

Every call to `stake()` appends the caller unconditionally:

```cairo
// Add staker address to the stakers vector.
self.stakers.push(staker_address);
```

`get_stakers` then iterates the **full** vector on every invocation:

```cairo
for staker_address_ptr in self.stakers.into_iter_full_range() {
    let staker_address = staker_address_ptr.read();
    if !self.is_staker_active(:staker_address, :epoch_id) {
        continue;
    }
    // ... per-staker storage reads ...
}
```

Even though inactive stakers are skipped with `continue`, every entry still costs a storage read. As the vector grows, the gas cost of `get_stakers` grows linearly and without bound.

The `assert_staker_address_not_reused` guard prevents the same address from staking twice, but it does **not** prevent an attacker from using a fresh address each cycle:

```cairo
fn assert_staker_address_not_reused(self: @ContractState, staker_address: ContractAddress) {
    assert!(
        self.staker_balance_trace.entry(key: staker_address).is_empty(), ...
    );
    assert!(
        self.staker_own_balance_trace.entry(key: staker_address).is_empty(), ...
    );
}
```

This only blocks address reuse; it does not limit the total number of distinct addresses that can be registered.

**Attack flow:**
1. Attacker holds `min_stake` STRK tokens.
2. Attacker calls `stake()` from address A → entry pushed to `stakers`.
3. Attacker calls `unstake_intent()` → waits `DEFAULT_EXIT_WAIT_WINDOW` (1 week).
4. Attacker calls `unstake_action()` → recovers `min_stake` tokens.
5. Attacker repeats from step 2 with address B, C, D, … recycling the same capital.
6. Each cycle permanently adds one dead entry to `stakers`.
7. After N cycles, `get_stakers` must perform N storage reads per call.

The attacker needs only `min_stake` tokens at any one time and can add ~52 entries per year per unit of capital. The damage is cumulative and irreversible.

---

### Impact Explanation

`get_stakers` is the function the consensus layer calls to obtain the current validator set. Once the `stakers` vector is large enough to push `get_stakers` past the Starknet transaction gas limit, the function becomes permanently uncallable. This constitutes **unbounded gas consumption** and **griefing with damage to the protocol** — the consensus layer loses the ability to read the validator set on-chain.

This matches the allowed Medium impact: *"Griefing with no profit motive but damage to users or protocol; Unbounded gas consumption."*

---

### Likelihood Explanation

- **Entry path is fully unprivileged**: any address with `min_stake` STRK can call `stake()`.
- **Capital requirement is low**: the attacker recycles the same `min_stake` tokens across all cycles.
- **Time cost is bounded**: one new dead entry per week per unit of capital.
- **Damage is permanent**: entries are never removed; there is no recovery path once the vector is large enough.
- **No detection or prevention mechanism** exists in the current code.

---

### Recommendation

1. **Lazy deletion / active-set tracking**: Maintain a separate counter or set of *currently active* stakers. `get_stakers` should iterate only active stakers, not the historical append-only vector.
2. **Alternatively, remove entries on `unstake_action`**: Replace the `Vec` with a data structure that supports O(1) removal (e.g., a swap-and-pop pattern or an `IterableMap`).
3. **Minimum stake increase / rate limiting**: Raise the economic cost of adding entries, though this does not fix the root cause.

---

### Proof of Concept

Root cause — `stakers` is append-only: [1](#0-0) 

Every `stake()` call appends unconditionally: [2](#0-1) 

`get_stakers` iterates the full historical vector: [3](#0-2) 

`assert_staker_address_not_reused` only blocks address reuse, not new addresses: [4](#0-3)

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
