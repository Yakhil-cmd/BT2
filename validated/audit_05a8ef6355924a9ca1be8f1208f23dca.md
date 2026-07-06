### Title
Permanent `stakers` Vector Bloat via Stake-Then-Unstake Cycle Enables Unbounded Gas Consumption in `get_stakers` - (File: `src/staking/staking.cairo`)

### Summary
The `min_stake` requirement is enforced only at `stake()` entry. After completing the `unstake_intent()` + `unstake_action()` exit cycle, a staker recovers their full STRK deposit, but their address is permanently appended to the `stakers` storage vector and can never be reused. Because `get_stakers()` iterates over the entire `stakers` vector unconditionally, an attacker can bloat this vector at the cost of only a one-week capital lock-up, eventually making `get_stakers()` too expensive to execute.

---

### Finding Description

`stake()` enforces a minimum deposit: [1](#0-0) 

Every successful `stake()` call permanently appends the caller to the `stakers` vector: [2](#0-1) 

The storage comment explicitly acknowledges stakers are never removed: [3](#0-2) 

After `unstake_action()`, `remove_staker()` writes a zero entry into `staker_own_balance_trace` but does **not** clear it: [4](#0-3) 

`assert_staker_address_not_reused()` then permanently blocks that address from ever staking again, because the trace is non-empty: [5](#0-4) 

`get_stakers()` iterates the **full** vector on every call: [6](#0-5) 

Each inactive staker still costs at least two storage reads per loop iteration (address read + `staker_info` read inside `is_staker_active()`). As the vector grows, the gas cost of `get_stakers()` grows linearly and without bound.

---

### Impact Explanation

`get_stakers()` is the consensus-layer entry point used to determine the validator set for a given epoch. If it runs out of gas, the protocol cannot produce a validator set, permanently freezing consensus reward distribution and blocking the attestation flow. This matches the allowed impact: **Unbounded gas consumption (Medium)**.

---

### Likelihood Explanation

The attack requires only:
1. `min_stake` STRK per address, locked for one `exit_wait_window` (default: 1 week).
2. After the week, all STRK is recovered via `unstake_action()`.
3. The attacker can parallelize across thousands of addresses simultaneously.

The net cost is the opportunity cost of locking STRK for one week per batch. With a sufficiently large STRK holding, an attacker can permanently add thousands of dead entries to the `stakers` vector in a single week-long cycle, with no ongoing cost thereafter.

---

### Recommendation

One of the following mitigations should be applied:

1. **Remove stakers from the vector on exit**: Replace the `Vec` with an `IterableMap` keyed by staker address so entries can be deleted when `remove_staker()` is called.
2. **Paginate `get_stakers()`**: Accept an offset/limit so the iteration is bounded per call.
3. **Maintain a separate active-staker count/set**: Track only currently-active stakers in a separate structure iterated by `get_stakers()`, and move addresses out of it on `unstake_intent()`.

---

### Proof of Concept

```
// Attacker controls addresses A_1 ... A_N, each funded with min_stake STRK.

for i in 1..N:
    // Step 1: Meet the minimum, get added to stakers vector permanently.
    staking.stake(reward_address, operational_address_i, min_stake)  // from A_i

// Wait for exit_wait_window (1 week) after calling unstake_intent for each.
for i in 1..N:
    staking.unstake_intent()   // from A_i  → sets exit timestamp
    // ... advance time by exit_wait_window ...
    staking.unstake_action(A_i) // full min_stake returned to A_i

// Now stakers vector has N extra dead entries.
// get_stakers(epoch_id) must iterate all N+original entries.
// With N large enough, get_stakers() exceeds the block gas limit.
staking.get_stakers(epoch_id)  // OUT OF GAS
```

The `min_stake` check at `stake()` entry is the only gate, but it does not prevent the permanent vector slot from being acquired and then abandoned after the exit window — a direct analog to the `MIN_MINT_DYAD_DEPOSIT` bypass in the referenced report.

### Citations

**File:** src/staking/staking.cairo (L168-169)
```text
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
```

**File:** src/staking/staking.cairo (L317-317)
```text
            assert!(amount >= self.min_stake.read(), "{}", Error::AMOUNT_LESS_THAN_MIN_STAKE);
```

**File:** src/staking/staking.cairo (L348-348)
```text
            self.stakers.push(staker_address);
```

**File:** src/staking/staking.cairo (L918-920)
```text
            for staker_address_ptr in self.stakers.into_iter_full_range() {
                let staker_address = staker_address_ptr.read();
                if !self.is_staker_active(:staker_address, :epoch_id) {
```

**File:** src/staking/staking.cairo (L1692-1692)
```text
            self.insert_staker_own_balance(:staker_address, own_balance: Zero::zero());
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
