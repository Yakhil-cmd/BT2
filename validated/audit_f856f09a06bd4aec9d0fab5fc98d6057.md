### Title
Unbounded `stakers` Vec Growth With No Removal Mechanism Causes Permanent DoS on `get_stakers()` - (File: src/staking/staking.cairo)

---

### Summary

The `stakers` storage Vec in `Staking` grows every time a new staker calls `stake()`, but stakers are **never removed** from it when they unstake. The `get_stakers()` function iterates over the entire Vec on every call. As the protocol accumulates historical stakers, this iteration will eventually exceed Starknet's block gas limit, permanently breaking `get_stakers()`.

---

### Finding Description

In `src/staking/staking.cairo`, the storage struct declares:

```
/// Vector of staker addresses.
/// **Note**: Stakers are not removed from this vector when they unstake.
stakers: Vec<ContractAddress>,
``` [1](#0-0) 

Every call to `stake()` appends the new staker's address unconditionally:

```cairo
// Add staker address to the stakers vector.
self.stakers.push(staker_address);
``` [2](#0-1) 

The public `get_stakers()` function then iterates over **the full range** of this Vec, including all historical stakers who have long since unstaked:

```cairo
for staker_address_ptr in self.stakers.into_iter_full_range() {
    let staker_address = staker_address_ptr.read();
    if !self.is_staker_active(:staker_address, :epoch_id) {
        continue;
    }
    ...
}
``` [3](#0-2) 

There is no corresponding removal of a staker address from `self.stakers` anywhere in `unstake_intent()` or `unstake_action()`. The `assert_staker_address_not_reused` guard further confirms that once an address stakes and unstakes, it can never re-stake — meaning every unique staker address permanently occupies a slot in the Vec. [4](#0-3) 

---

### Impact Explanation

`get_stakers()` is the primary interface used by the consensus layer to determine validator weights and staking power per epoch. As the Vec grows with historical (inactive) stakers, each call to `get_stakers()` must read and check every entry. Once the Vec is large enough, the call will exceed Starknet's block gas limit, permanently breaking the function. This constitutes **unbounded gas consumption** and eventual permanent DoS on a critical protocol function.

Impact: **Medium — Unbounded gas consumption / griefing with damage to the protocol.**

---

### Likelihood Explanation

Growth occurs through two paths:

1. **Organic**: Every legitimate staker who ever stakes and later unstakes permanently inflates the Vec. In a live protocol with high staker turnover, this grows naturally over time.
2. **Adversarial**: An unprivileged attacker can accelerate growth by cycling through many addresses (each meeting the minimum stake requirement), staking and unstaking to bloat the Vec. The minimum stake is a cost barrier but not a fundamental prevention.

The `assert_staker_address_not_reused` check means each address contributes exactly one permanent entry, so the Vec size equals the total number of unique stakers ever registered. [5](#0-4) 

---

### Recommendation

Remove the staker's address from `self.stakers` during `unstake_action()` (swap-and-pop pattern), or replace the `Vec` with an `IterableMap` that supports deletion (as already used for `btc_tokens`). Alternatively, expose a paginated version of `get_stakers()` that accepts an index range, so callers can retrieve results in bounded chunks even if the Vec grows large. [6](#0-5) 

---

### Proof of Concept

1. Deploy the staking contract.
2. Register N unique staker addresses, each calling `stake()` with the minimum stake amount. Each call appends to `self.stakers`.
3. Have each staker call `unstake_intent()` then `unstake_action()` to recover funds. Their addresses remain in `self.stakers`.
4. Call `get_stakers(epoch_id)`. The function iterates all N entries, performing storage reads and `is_staker_active` checks for each. As N grows, gas consumption grows linearly.
5. At sufficiently large N, the call reverts with out-of-gas, permanently breaking `get_stakers()`.

The test `DiverseStakerVecFlow` already confirms that stakers who have completed `exit_action` remain in the Vec at index 3 (`staker_in_action`), and `get_stakers()` still returns all 4 entries: [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L166-169)
```text
        btc_tokens: IterableMap<ContractAddress, (Epoch, bool)>,
        /// Vector of staker addresses.
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
```

**File:** src/staking/staking.cairo (L347-348)
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

**File:** src/flow_test/flows.cairo (L5892-5903)
```text
        system.staker_exit_intent(staker: staker_in_action);
        system.advance_time(time: system.staking.get_exit_wait_window());
        system.staker_exit_action(staker: staker_in_action);

        system.staker_exit_intent(staker: staker_in_intent);

        let actual_stakers = system.staking.get_stakers();
        assert!(actual_stakers.len() == 4);
        assert!(actual_stakers.at(index: 0) == @staker_with_pool.staker.address);
        assert!(actual_stakers.at(index: 1) == @staker_without_pool.staker.address);
        assert!(actual_stakers.at(index: 2) == @staker_in_intent.staker.address);
        assert!(actual_stakers.at(index: 3) == @staker_in_action.staker.address);
```
