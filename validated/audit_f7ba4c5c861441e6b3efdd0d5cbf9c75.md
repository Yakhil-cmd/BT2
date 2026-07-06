### Title
Unbounded `stakers` Vec Growth via Repeated Stake/Unstake Cycles Causes Permanent DoS of `get_stakers` — (`src/staking/staking.cairo`)

---

### Summary

The `stakers` storage Vec is append-only by design: every `stake()` call pushes a new address, but `unstake_action()` / `remove_staker()` never removes it. `get_stakers()` iterates the **full** Vec on every call. An unprivileged attacker cycling N unique addresses through `stake → unstake_intent → unstake_action` grows the Vec to size N at a cost of only gas per cycle (STRK is recovered each time), eventually making `get_stakers()` exceed the block gas limit permanently.

---

### Finding Description

**Storage declaration — append-only by design:** [1](#0-0) 

The comment is explicit: stakers are never removed from this Vec.

**`stake()` pushes unconditionally:** [2](#0-1) 

**`remove_staker()` never touches `self.stakers`:** [3](#0-2) 

It clears `staker_info`, `operational_address_to_staker_address`, and commission fields — but the address remains in the Vec forever.

**`get_stakers()` iterates the full Vec on every call:** [4](#0-3) 

Even dead stakers (those that passed through `unstake_action`) are read from storage on every iteration; they are merely skipped via `is_staker_active`. Each dead entry still costs a storage read.

---

### Impact Explanation

Once the Vec reaches a size where iterating it exceeds the Starknet block gas limit, every call to `get_stakers()` reverts. This is the consensus endpoint used by validators to determine the active staker set for a given epoch. A permanent revert here breaks the consensus layer's ability to query staking power, constituting a permanent denial of service for that endpoint.

---

### Likelihood Explanation

The attack is economically cheap. The attacker only needs `min_stake` STRK at any one time: stake with address A₁, wait for `exit_wait_window`, call `unstake_action` to recover the STRK, transfer to A₂, repeat. Each cycle costs only gas and adds one permanent dead entry to the Vec. No privileged role is required; `stake()` and `unstake_action()` are fully public.

The `assert_staker_address_not_reused` guard prevents the *same* address from re-staking, but does not prevent N *distinct* addresses from each staking once and unstaking, which is the attack vector here. [5](#0-4) 

---

### Recommendation

One of the following mitigations:

1. **Swap-and-pop on unstake**: When `remove_staker` is called, swap the departing address with the last element in `self.stakers` and pop the tail. This keeps the Vec compact at the cost of O(1) extra work per unstake.
2. **Lazy compaction**: Record a "dead" bitmap alongside the Vec and periodically compact it via a permissioned maintenance call.
3. **Cap the staker count**: Enforce a maximum Vec size in `stake()`, preventing unbounded growth at the protocol level.

---

### Proof of Concept

```
// Pseudocode — repeat N times with fresh address Aᵢ each iteration:
for i in 0..N:
    transfer(min_stake, Aᵢ)
    Aᵢ.approve(staking_contract, min_stake)
    staking_contract.stake(Aᵢ, min_stake, ...)   // stakers.push(Aᵢ) → Vec grows
    staking_contract.unstake_intent()              // called as Aᵢ
    advance_time(exit_wait_window)
    staking_contract.unstake_action(Aᵢ)           // STRK returned; Vec NOT shrunk
    transfer(min_stake, Aᵢ₊₁)                     // recycle funds

// After N cycles: stakers.len() == N (all dead)
// get_stakers() now iterates N storage reads → OOG for large N
staking_consensus.get_stakers(epoch_id)  // reverts permanently
```

The invariant `gas(get_stakers) ≤ C` is violated for sufficiently large N, confirming the unbounded gas consumption impact.

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

**File:** src/staking/staking.cairo (L347-349)
```text
            // Add staker address to the stakers vector.
            self.stakers.push(staker_address);

```

**File:** src/staking/staking.cairo (L918-922)
```text
            for staker_address_ptr in self.stakers.into_iter_full_range() {
                let staker_address = staker_address_ptr.read();
                if !self.is_staker_active(:staker_address, :epoch_id) {
                    continue;
                }
```

**File:** src/staking/staking.cairo (L1686-1708)
```text
        fn remove_staker(
            ref self: ContractState,
            staker_address: ContractAddress,
            staker_info: InternalStakerInfoLatest,
            staker_pool_info: StoragePath<Mutable<InternalStakerPoolInfoV2>>,
        ) {
            self.insert_staker_own_balance(:staker_address, own_balance: Zero::zero());
            self.staker_info.write(staker_address, VInternalStakerInfo::None);
            let operational_address = staker_info.operational_address;
            self.operational_address_to_staker_address.write(operational_address, Zero::zero());
            staker_pool_info.commission.write(Option::None);
            staker_pool_info.commission_commitment.write(Option::None);
            let pool_contracts = staker_pool_info.get_pools();
            self
                .emit(
                    Events::DeleteStaker {
                        staker_address,
                        reward_address: staker_info.reward_address,
                        operational_address,
                        pool_contracts,
                    },
                );
        }
```
