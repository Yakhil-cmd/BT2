### Title
Unbounded `stakers` Vec Growth Causes Permanent DoS of `get_stakers` — (File: src/staking/staking.cairo)

---

### Summary

The `stakers` Vec in the `Staking` contract is append-only: every call to `stake()` pushes the caller's address into the Vec, but `unstake_action()` never removes it. The `get_stakers` function iterates over the **entire** Vec on every call. Because any unprivileged address can stake the minimum amount, wait out the exit window, and unstake — leaving a dead entry in the Vec — an attacker (or simply organic churn over time) can grow the Vec without bound, eventually making `get_stakers` too expensive to execute.

---

### Finding Description

**Root cause — append-only `stakers` Vec:**

In `staking.cairo`, the storage field is declared with an explicit note that entries are never cleaned up:

```
/// Vector of staker addresses.
/// **Note**: Stakers are not removed from this vector when they unstake.
stakers: Vec<ContractAddress>,
``` [1](#0-0) 

Every successful `stake()` call appends to this Vec:

```cairo
// Add staker address to the stakers vector.
self.stakers.push(staker_address);
``` [2](#0-1) 

`unstake_action()` calls `remove_staker` and clears pool data, but the address already pushed into `stakers` is never popped or zeroed. [3](#0-2) 

**Consumption site — full-range iteration in `get_stakers`:**

`get_stakers` is the function the consensus layer calls to build the validator set for a given epoch. It unconditionally iterates over every element ever pushed:

```cairo
for staker_address_ptr in self.stakers.into_iter_full_range() {
    let staker_address = staker_address_ptr.read();
    if !self.is_staker_active(:staker_address, :epoch_id) {
        continue;
    }
    ...
}
``` [4](#0-3) 

Inactive (unstaked) entries are skipped with `continue`, but they are still **read from storage** on every call. Each storage read costs execution steps. As the Vec grows, the step count grows linearly with the total number of addresses that have ever staked, not with the number currently active.

---

### Impact Explanation

`get_stakers` is the sole on-chain source of the validator set used by the consensus layer. Once the Vec is large enough that a single call to `get_stakers` exceeds Starknet's per-call execution-step budget, the function becomes permanently uncallable. This constitutes **unbounded gas consumption** leading to a protocol-level griefing: the consensus layer can no longer retrieve the active staker set, disrupting validator selection and reward distribution for all participants.

**Allowed impact matched:** Medium — Unbounded gas consumption / Griefing with damage to the protocol.

---

### Likelihood Explanation

The entry path is fully unprivileged. Any address that holds the minimum stake amount can:

1. Call `stake()` → address appended to `stakers`.
2. Call `unstake_intent()` → wait `DEFAULT_EXIT_WAIT_WINDOW` (1 week).
3. Call `unstake_action()` → funds returned, but dead entry remains in Vec.
4. Repeat with a fresh address.

Each cycle costs only `min_stake` STRK plus gas. The attacker recovers their principal after each cycle (minus gas). Even without a deliberate attacker, organic protocol usage — legitimate stakers who stake once and later fully exit — permanently inflates the Vec. Over a multi-year protocol lifetime this is a near-certainty.

---

### Recommendation

One of the following mitigations should be applied:

1. **Swap-and-pop on unstake**: When `unstake_action` is called, find the staker's index in the Vec, swap it with the last element, and pop the last element. This keeps the Vec compact.
2. **Active-staker count + skip-list**: Maintain a separate `active_staker_count` and a mapping from address to Vec index so that `get_stakers` can skip dead entries without reading them from storage.
3. **Paginated iteration**: Add a paginated variant of `get_stakers` that accepts a start index and page size, so callers can split the work across multiple calls even if the Vec is large.

---

### Proof of Concept

```
// Attacker script (pseudocode):
for i in 0..N:
    addr_i = fresh_address()
    strk.transfer(addr_i, min_stake)
    staking.stake(reward_addr, op_addr, min_stake)  // from addr_i
    staking.unstake_intent()                         // from addr_i
    wait(DEFAULT_EXIT_WAIT_WINDOW)
    staking.unstake_action(addr_i)                   // from anyone
    // addr_i is now in stakers[] forever, staker_info is None

// After N iterations:
// stakers.len() == N (all inactive)
// get_stakers(epoch) iterates N storage reads → O(N) steps
// At sufficiently large N, get_stakers() exceeds the step budget and reverts
```

The attacker recovers `min_stake * N` STRK (minus gas), making the net cost purely gas — a cheap, permanent griefing vector against the consensus layer's ability to read the validator set.

### Citations

**File:** src/staking/staking.cairo (L168-169)
```text
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
```

**File:** src/staking/staking.cairo (L347-348)
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
