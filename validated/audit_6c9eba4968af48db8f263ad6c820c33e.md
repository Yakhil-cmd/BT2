### Title
Unbounded Iteration Over Append-Only `stakers` Vec in `get_stakers` Causes Unbounded Gas Consumption — (File: `src/staking/staking.cairo`)

---

### Summary
The `stakers` storage Vec in the Staking contract is append-only: every new staker address is pushed in, and the code explicitly documents that addresses are **never removed** when a staker unstakes. The `get_stakers` function iterates over the entire Vec on every call, including entries for long-gone stakers. Because any address may call `get_stakers`, an adversary can bloat the Vec by registering many staker accounts (each at minimum stake), permanently increasing the per-call gas cost for all future callers, including the consensus layer.

---

### Finding Description

**Root cause — append-only `stakers` Vec:**

The storage declaration carries an explicit warning:

```
/// Vector of staker addresses.
/// **Note**: Stakers are not removed from this vector when they unstake.
stakers: Vec<ContractAddress>,
``` [1](#0-0) 

Every successful `stake()` call appends the caller's address unconditionally:

```cairo
// Add staker address to the stakers vector.
self.stakers.push(staker_address);
``` [2](#0-1) 

**Root cause — full-range iteration in `get_stakers`:**

`get_stakers` iterates over the entire Vec with `into_iter_full_range()`, performing multiple storage reads and computations per entry (staker info, staking power, public key, peer id):

```cairo
for staker_address_ptr in self.stakers.into_iter_full_range() {
    let staker_address = staker_address_ptr.read();
    if !self.is_staker_active(:staker_address, :epoch_id) {
        continue;
    }
    let staking_power = self
        .get_staker_staking_power_at_epoch(...);
    ...
    let public_key = self.get_public_key_at_epoch(...);
    let peer_id   = self.get_peer_id_at_epoch(...);
    stakers.append(...);
}
``` [3](#0-2) 

Inactive stakers are skipped by the `continue`, but the Vec slot is still read and the `is_staker_active` check still executes a storage read for every historical staker address. There is no pruning, pagination, or upper-bound guard.

**Access control — any address:**

Per the specification, `get_stakers` is callable by any address:

```
#### access control
Any address.
``` [4](#0-3) 

---

### Impact Explanation

As the Vec grows, the gas cost of `get_stakers` grows linearly with the total number of stakers ever registered (not just active ones). Once the Vec is large enough, the function will exceed the Starknet block gas limit and revert on every call. This permanently breaks the consensus layer's ability to query staking power for any epoch, which is the mechanism by which validators are selected and rewards are distributed. The impact matches **Medium: Griefing with no profit motive but damage to users or protocol** and **Medium: Unbounded gas consumption**.

---

### Likelihood Explanation

The minimum stake is a protocol parameter, but it is finite. An adversary (or organic protocol growth) can register thousands of staker accounts over time. Because unstaked addresses are never removed, the Vec is monotonically growing. The attack requires no privileged access — only the ability to call `stake()` with the minimum required amount, which is available to any address. At sufficient scale (thousands of historical stakers), `get_stakers` becomes uncallable.

---

### Recommendation

1. **Lazy deletion / active-set index**: Maintain a separate, compactable data structure (e.g., an `IterableMap` keyed by staker address) that removes entries on `unstake_action`, so iteration is bounded by the number of *currently active* stakers.
2. **Pagination**: Add an optional `(offset, limit)` parameter to `get_stakers` so callers can process the set in bounded batches.
3. **Active-staker counter**: Track a separate count of active stakers and enforce a protocol-level cap, or at minimum expose it so off-chain tooling can warn before the limit is approached.

---

### Proof of Concept

1. Deploy the Staking contract with `min_stake = M`.
2. Register `N` staker accounts (each funded with `M` STRK), calling `stake()` for each. Each call appends one address to `self.stakers`.
3. Have all `N` stakers call `unstake_intent()` and then `unstake_action()`. Their entries remain in the Vec.
4. Call `get_stakers(epoch_id)`. The function iterates all `N` slots, performing at minimum one storage read per slot for `is_staker_active`. At large `N`, the transaction reverts with an out-of-gas error.
5. The consensus layer can no longer retrieve the staker set for any epoch, breaking reward distribution. [5](#0-4) [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L167-169)
```text
        /// Vector of staker addresses.
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
```

**File:** src/staking/staking.cairo (L344-349)
```text
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

**File:** docs/spec.md (L1672-1672)
```markdown
Any address.
```
