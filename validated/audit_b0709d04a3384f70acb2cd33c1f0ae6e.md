### Title
Unbounded `stakers` Vec Growth Enables Permanent Griefing of `get_stakers()` via Stake/Unstake Cycling — (File: `src/staking/staking.cairo`)

---

### Summary

Every call to `stake()` appends the caller's address to the global `stakers: Vec<ContractAddress>`. Stakers are **never removed** from this Vec, even after `unstake_action()` completes. The `get_stakers()` function iterates over the **entire** Vec on every call. An unprivileged attacker can cycle through many addresses — staking the minimum amount, waiting out the exit window, and recovering their funds — while permanently bloating the Vec. Once the Vec is large enough, `get_stakers()` exceeds Starknet's execution resource limits and becomes permanently unusable, breaking the consensus validator-set query.

---

### Finding Description

**Root cause — append-only `stakers` Vec:**

Every `stake()` call unconditionally pushes the caller's address:

```cairo
// Add staker address to the stakers vector.
self.stakers.push(staker_address);
``` [1](#0-0) 

The storage declaration itself carries an explicit warning that entries are never cleaned up:

```cairo
/// Vector of staker addresses.
/// **Note**: Stakers are not removed from this vector when they unstake.
stakers: Vec<ContractAddress>,
``` [2](#0-1) 

`remove_staker()`, called during `unstake_action()`, clears `staker_info`, the operational-address mapping, commission fields, and pool data — but never touches `self.stakers`: [3](#0-2) 

**Victim function — full Vec iteration in `get_stakers()`:**

```cairo
for staker_address_ptr in self.stakers.into_iter_full_range() {
    let staker_address = staker_address_ptr.read();
    if !self.is_staker_active(:staker_address, :epoch_id) {
        continue;
    }
    // ... per-staker storage reads ...
}
``` [4](#0-3) 

Every iteration step reads storage for every address ever registered, including long-since-removed stakers. There is no upper bound on the Vec length.

**Attack path:**

1. Attacker controls N addresses, each pre-funded with `min_stake` STRK.
2. Each address calls `stake()` → appends one entry to `self.stakers`.
3. Each address calls `unstake_intent()` → sets exit timestamp.
4. After `exit_wait_window` (default 1 week), each address calls `unstake_action()` → recovers all STRK.
5. The N addresses remain in `self.stakers` permanently.
6. Repeat with fresh addresses to grow the Vec further.

The attacker recovers their principal; the only cost is the opportunity cost of locking `min_stake × N` STRK for one week per batch.

`assert_staker_address_not_reused` prevents re-staking from the same address, so each iteration requires a fresh address, but addresses are cheap to generate on Starknet. [5](#0-4) 

---

### Impact Explanation

`get_stakers()` is the protocol's canonical validator-set query, called by the consensus layer to determine staking power per epoch: [6](#0-5) 

Once the Vec exceeds Starknet's per-call execution resource ceiling, every invocation of `get_stakers()` reverts. The consensus layer can no longer retrieve the active validator set, permanently breaking the on-chain consensus interface. This constitutes **unbounded gas consumption** and **griefing with damage to the protocol** — matching the Medium impact tier.

---

### Likelihood Explanation

- `stake()` is permissionless; any address meeting `min_stake` can call it.
- Funds are fully recoverable after the exit window, so the net cost to the attacker is only capital lock-up time.
- The attack is incremental: the attacker does not need to execute all iterations at once; each weekly cycle permanently adds entries.
- No privileged access, leaked keys, or external dependencies are required.

---

### Recommendation

Remove a staker's address from `self.stakers` when `unstake_action()` is called, or replace the append-only `Vec` with a data structure that supports O(1) deletion (e.g., a swap-and-pop pattern using an index map). Alternatively, cap the maximum number of registered stakers or introduce a tombstone flag so `get_stakers()` can skip removed entries without reading unbounded storage.

---

### Proof of Concept

```
1. Deploy N fresh accounts, each holding min_stake STRK.
2. For each account i in [1..N]:
     account_i.approve(staking_contract, min_stake)
     staking_contract.stake(reward_addr_i, op_addr_i, min_stake)
     // self.stakers now has length i
3. Advance time by exit_wait_window.
4. For each account i:
     staking_contract.unstake_intent()   // called as account_i
     staking_contract.unstake_action(account_i)
     // STRK returned; self.stakers[i] entry remains forever
5. Repeat steps 1-4 with fresh accounts until self.stakers.len() exceeds
   the Starknet execution resource limit for a single call.
6. Call staking_contract.get_stakers(current_epoch) → reverts with
   resource exhaustion; consensus validator-set query is permanently broken.
```

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
