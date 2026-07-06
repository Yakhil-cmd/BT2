### Title
Unbounded Growth of `stakers` Vec Causes Unbounded Gas Consumption in `get_stakers` - (File: `src/staking/staking.cairo`)

### Summary
The `stakers` storage Vec in the Staking contract is append-only. Every call to `stake()` pushes a new address into it, but no code path ever removes an address after a staker exits. The `get_stakers` function iterates over the **entire** Vec on every call. Over time, as stakers enter and exit, the Vec grows without bound, making `get_stakers` progressively more expensive until it exceeds the block gas limit and becomes permanently uncallable.

### Finding Description

When a new staker registers, their address is pushed into the `stakers` Vec: [1](#0-0) 

There is no corresponding removal when a staker calls `unstake_intent` + `unstake_action`. The `stakers` Vec is strictly monotonically growing.

`get_stakers` iterates over the full range of this Vec on every invocation: [2](#0-1) 

Although inactive stakers are skipped via `is_staker_active` and `staking_power.is_zero()` checks, the loop body still executes a storage read (`staker_address_ptr.read()`) and at minimum one additional storage read for `is_staker_active` for **every** historical entry, including long-exited stakers. The gas cost is therefore O(total stakers ever registered), not O(currently active stakers).

The analog to the original report is exact:
- Original: `addTradeTokenCollateral` increments a counter on deposit; `subTradeTokenCollateral` is never called on withdrawal → counter grows monotonically → hits `collateralTotalCap` → `deposit` reverts.
- Here: `stakers.push()` is called on every `stake()`; no removal on exit → Vec grows monotonically → `get_stakers` gas cost grows without bound → call eventually reverts.

### Impact Explanation

`get_stakers` is the consensus-layer entrypoint that returns the validator set for a given epoch: [3](#0-2) 

If this function becomes uncallable due to gas exhaustion, the consensus layer cannot retrieve the validator set, breaking the protocol's ability to operate. This constitutes **unbounded gas consumption** leading to permanent denial of service of a critical protocol function.

Impact classification: **Medium — Unbounded gas consumption / griefing with damage to the protocol.**

### Likelihood Explanation

An unprivileged attacker needs only to:
1. Obtain STRK tokens equal to `min_stake` per address.
2. Call `stake()` from a fresh address, then `unstake_intent()` + `unstake_action()` after the exit window.
3. Repeat with a new address (the `assert_staker_address_not_reused` check prevents reuse of the same address, but different addresses are trivially generated).

The attacker recovers their principal on each cycle; the only cost is gas. The `stakers` Vec grows by one entry per cycle. Because Starknet has a finite per-transaction gas limit, a sufficiently large Vec will cause `get_stakers` to revert. The number of cycles required is bounded by `gas_limit / gas_per_iteration`, which is finite and achievable.

### Recommendation

Remove exited stakers from the `stakers` Vec, or replace the Vec with a structure that supports deletion (e.g., a swap-and-pop pattern). Alternatively, maintain a separate `active_stakers` count and only store currently-active stakers in the iterable collection, moving exited stakers to a tombstone set that is not iterated in `get_stakers`.

### Proof of Concept

1. Deploy the staking contract with `min_stake = M`.
2. For `i = 1..N`, using address `addr_i`:
   - Approve and call `stake(addr_i, reward_addr, op_addr, M)`.
   - Advance time past `exit_wait_window`.
   - Call `unstake_intent(addr_i)`, advance time, call `unstake_action(addr_i)`.
3. After `N` iterations, `self.stakers` contains `N` entries (all exited).
4. Call `get_stakers(epoch_id: current_epoch)`.
5. Observe that the call iterates over all `N` entries. For large enough `N`, the transaction runs out of gas and reverts.

The `stakers` Vec is the only data structure iterated in `get_stakers`: [4](#0-3) 

and it is only ever written to via `push`: [5](#0-4) 

with no corresponding removal anywhere in the contract.

### Citations

**File:** src/staking/staking.cairo (L347-349)
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
