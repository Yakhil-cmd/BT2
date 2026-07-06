### Title
Unbounded Growth of `stakers` Vec Enables Griefing via Unbounded Gas Consumption in `get_stakers()` - (File: src/staking/staking.cairo)

### Summary
The `stakers` storage Vec in the `Staking` contract is append-only: staker addresses are pushed on every `stake()` call but are **never removed** when a staker unstakes. The `get_stakers()` function iterates over the entire Vec on every call. An attacker can inflate this Vec by repeatedly staking with fresh addresses and then unstaking, causing `get_stakers()` to consume unbounded gas and eventually become uncallable.

### Finding Description

The `stakers` Vec is declared in storage with an explicit developer note acknowledging the design:

> `/// **Note**: Stakers are not removed from this vector when they unstake.`
> `stakers: Vec<ContractAddress>,` [1](#0-0) 

Every call to `stake()` unconditionally appends the new staker address:

```cairo
// Add staker address to the stakers vector.
self.stakers.push(staker_address);
``` [2](#0-1) 

The `remove_staker()` internal function — called during `unstake_action()` — clears `staker_info`, zeroes the operational address mapping, and emits `DeleteStaker`, but **never touches `self.stakers`**: [3](#0-2) 

`get_stakers()` iterates over the **full range** of the Vec on every invocation:

```cairo
for staker_address_ptr in self.stakers.into_iter_full_range() {
    let staker_address = staker_address_ptr.read();
    if !self.is_staker_active(:staker_address, :epoch_id) {
        continue;
    }
    ...
}
``` [4](#0-3) 

Stale (unstaked) addresses are skipped via `is_staker_active`, but the loop body — including the storage read of `staker_address_ptr.read()` and the `is_staker_active` check — still executes for every entry. Each iteration costs gas proportional to the number of storage reads, so a Vec with N stale entries costs O(N) gas regardless of how many active stakers exist.

### Impact Explanation

`get_stakers()` is the `IStakingConsensus` entrypoint used by the consensus layer to determine the validator set for a given epoch. If the `stakers` Vec is inflated to a sufficiently large size, every call to `get_stakers()` will hit the Starknet transaction gas limit and revert. This permanently breaks the ability of the consensus layer to read the validator set, constituting a griefing attack that damages the protocol with no profit motive for the attacker.

**Impact: Medium — Griefing / Unbounded gas consumption.**

### Likelihood Explanation

The attack requires the attacker to stake with many distinct addresses (since `assert_staker_address_not_reused` prevents re-staking from the same address after unstaking). Each address must hold at least `min_stake` STRK. This is a capital cost, but:

- A flash loan can fund many addresses in a single transaction.
- Even without a deliberate attack, organic protocol usage (stakers joining and leaving over months/years) will cause the Vec to grow without bound, eventually degrading `get_stakers()` performance for all callers. [5](#0-4) 

### Recommendation

Remove the staker address from `self.stakers` during `remove_staker()`, or replace the `Vec` with a data structure that supports O(1) deletion (e.g., a swap-and-pop pattern using an index map). Alternatively, maintain a separate counter of active stakers and enforce a cap, or use a lazy-deletion bitmap so that `get_stakers()` can skip stale entries without a full storage read per slot.

### Proof of Concept

```
// Attacker controls N addresses, each funded with min_stake STRK.
for i in 0..N:
    staking.stake(attacker_address[i], min_stake, ...)   // pushes to stakers Vec
    staking.unstake_intent()                              // marks exit
    advance_time(exit_wait_window)
    staking.unstake_action(attacker_address[i])           // removes staker_info but NOT from Vec

// Now self.stakers.len() == N (all stale).
// Any call to get_stakers() must iterate all N entries.
// For large N, get_stakers() exceeds the block gas limit and reverts.
staking_consensus.get_stakers(epoch_id)  // OOG / permanent DoS
```

The `stakers` Vec length is observable on-chain and grows monotonically. The attacker recovers their `min_stake` after each `unstake_action`, so the net cost per slot inflated is only the gas for the stake/unstake cycle, not the principal.

### Citations

**File:** src/staking/staking.cairo (L167-169)
```text
        /// Vector of staker addresses.
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
```

**File:** src/staking/staking.cairo (L301-303)
```text
                Error::OPERATIONAL_EXISTS,
            );
            self.assert_staker_address_not_reused(:staker_address);
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
