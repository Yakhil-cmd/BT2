### Title
Unbounded `stakers` Vec Iteration in `get_stakers` Enables Gas DoS — (File: `src/staking/staking.cairo`)

---

### Summary
The `get_stakers` function iterates over a `Vec<ContractAddress>` called `stakers` that grows monotonically with every `stake()` call and is **never pruned when stakers unstake**. An unprivileged attacker can register arbitrarily many staker addresses with the minimum stake, recover all funds after the exit window, and permanently bloat the Vec, making `get_stakers` prohibitively expensive to execute.

---

### Finding Description

In `src/staking/staking.cairo`, the storage field `stakers` is declared as:

```
/// Vector of staker addresses.
/// **Note**: Stakers are not removed from this vector when they unstake.
stakers: Vec<ContractAddress>,
``` [1](#0-0) 

Every call to `stake()` unconditionally appends the caller's address to this Vec:

```cairo
// Add staker address to the stakers vector.
self.stakers.push(staker_address);
``` [2](#0-1) 

The `get_stakers` function then iterates over the **entire Vec** on every invocation, with no upper bound:

```cairo
for staker_address_ptr in self.stakers.into_iter_full_range() {
    let staker_address = staker_address_ptr.read();
    if !self.is_staker_active(:staker_address, :epoch_id) {
        continue;
    }
    // ... per-staker storage reads for staking power, public key, peer id
}
``` [3](#0-2) 

Each iteration performs multiple storage reads (`is_staker_active`, `get_staker_staking_power_at_epoch`, `get_public_key_at_epoch`, `get_peer_id_at_epoch`). Exited stakers are skipped via `continue` but still consume a storage read per entry. Because the Vec is never compacted, every historical staker address — including those who have fully unstaked — is visited on every call.

---

### Impact Explanation

`get_stakers` is the function the consensus layer calls to determine the active validator set for a given epoch. Its access control is **"Any address"** and it is part of `IStakingConsensus`. [4](#0-3) 

If the `stakers` Vec is bloated to a sufficiently large size, the execution resources required to complete `get_stakers` exceed Starknet's per-call execution limits, causing the call to fail. This prevents the consensus layer from reading the validator set, constituting **unbounded gas consumption** that degrades or halts a core protocol function.

---

### Likelihood Explanation

The attack is economically near-free: the attacker stakes the minimum amount per address, waits for the exit window, calls `unstake_action` to recover all principal, and the Vec entry remains permanently. The only sunk cost is gas for the registration and exit transactions. With enough addresses (each requiring only `min_stake` STRK temporarily), the Vec can be grown to any size. The `assert_staker_address_not_reused` check prevents reuse of the same address, but the attacker simply uses fresh addresses. [5](#0-4) 

---

### Recommendation

1. **Remove exited stakers from the Vec** by swapping the exited address with the last element and popping, or by using a separate active-staker set.
2. Alternatively, maintain a separate `active_stakers: Vec<ContractAddress>` that is pruned on `unstake_action`, and iterate only over that in `get_stakers`.
3. As a short-term mitigation, enforce a protocol-level cap on the total number of registered stakers.

---

### Proof of Concept

```
1. Attacker controls N addresses: A_1, A_2, ..., A_N.
2. For each A_i:
   a. Approve min_stake STRK to the staking contract.
   b. Call stake(reward_address, operational_address_i, amount=min_stake, ...).
      → stakers.push(A_i) executes; Vec length grows by 1.
3. After K epochs, for each A_i:
   a. Call unstake_intent().
   b. Wait for exit_wait_window.
   c. Call unstake_action() → principal returned; A_i remains in stakers Vec.
4. Now stakers.len() == N (plus any legitimate stakers).
5. Any call to get_stakers(epoch_id) must iterate all N entries,
   performing multiple storage reads per entry.
6. For sufficiently large N, the call exhausts execution resources and reverts,
   making the validator-set query permanently unavailable.
``` [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L167-169)
```text
        /// Vector of staker addresses.
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
```

**File:** src/staking/staking.cairo (L303-303)
```text
            self.assert_staker_address_not_reused(:staker_address);
```

**File:** src/staking/staking.cairo (L347-348)
```text
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

**File:** docs/spec.md (L1654-1672)
```markdown
### get_stakers
```rust
fn get_stakers(self: @TContractState, epoch_id: Epoch) -> Span<(ContractAddress, StakingPower, Option<PublicKey>, Option<PeerId>)>
```
#### description <!-- omit from toc -->
Returns a span of (staker_address, staking_power, Option<public_key>, Option<peer_id>) for all stakers
for the given `epoch_id`.
**Note**: The staking power is the relative weight of the staker's stake
out of the total stake, including pooled stake (STRK and BTC), multiplied by
`STAKING_POWER_BASE_VALUE`.
**Note**: Disregards stakers that either no staking power, which can be either new stakers
or stakers that called `exit_intent`.
#### emits <!-- omit from toc -->
#### errors <!-- omit from toc -->
1. [INVALID\_EPOCH](#invalid_epoch)
#### pre-condition <!-- omit from toc -->
`curr_epoch <= epoch_id < curr_epoch + K`.
#### access control <!-- omit from toc -->
Any address.
```
