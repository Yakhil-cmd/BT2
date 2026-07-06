### Title
Unbounded Growth of `stakers` Vec Causes Permanent DoS on `get_stakers()` via Unbounded Gas Consumption - (File: `src/staking/staking.cairo`)

---

### Summary

The `stakers` storage Vec in `Staking` is appended to on every `stake()` call but entries are **never removed** when a staker exits. The `get_stakers()` function iterates over the entire Vec on every call. An attacker can inflate the Vec with exited staker addresses at the cost of minimum-stake capital (fully recoverable), making `get_stakers()` permanently consume unbounded gas and eventually become uncallable.

---

### Finding Description

`staking.cairo` stores all staker addresses in a `Vec<ContractAddress>` with an explicit design note:

> **Note**: Stakers are not removed from this vector when they unstake. [1](#0-0) 

On every `stake()` call the address is appended: [2](#0-1) 

On `unstake_action()`, `remove_staker()` is called which deletes the `staker_info` record from storage, but the address is **never removed from `self.stakers`**: [3](#0-2) 

`get_stakers()` iterates over `self.stakers.into_iter_full_range()` — the **complete** Vec including all historical exited stakers — performing multiple storage reads per entry (`is_staker_active`, `get_staker_staking_power_at_epoch`, `get_public_key_at_epoch`, `get_peer_id_at_epoch`): [4](#0-3) 

Each exited staker still costs gas to process (a storage read for `staker_info` in `is_staker_active`, which returns `false` and causes a `continue`), but the cost is paid on every single `get_stakers()` invocation. [5](#0-4) 

---

### Impact Explanation

`get_stakers()` is the consensus-layer entry point used to determine the active validator set for each epoch. If the `stakers` Vec grows large enough, every call to `get_stakers()` will exceed the Starknet block gas limit, permanently preventing the consensus layer from reading the validator set. This constitutes **unbounded gas consumption** and a permanent griefing DoS against the protocol's consensus infrastructure.

**Impact: Medium** — Griefing with no profit motive but damage to users or protocol; Unbounded gas consumption.

---

### Likelihood Explanation

The attack is fully permissionless: any address can call `stake()` with the minimum stake amount, then call `unstake_intent()` and `unstake_action()` after the exit window to recover all capital. The only cost is transaction fees and the time-lock of capital during the exit window. An attacker can automate this across thousands of fresh addresses. Because the capital is fully recoverable, the economic barrier is only gas fees, making this a low-cost, high-impact griefing vector.

---

### Recommendation

Track exited stakers separately or use a data structure that supports removal. One approach is to maintain a separate `active_stakers_count` and use a swap-and-pop pattern on the Vec when a staker exits. Alternatively, `get_stakers()` could be redesigned to iterate only over a bounded active-staker set rather than the full historical Vec. At minimum, the protocol should enforce an upper bound on the total number of registered staker addresses.

---

### Proof of Concept

1. Attacker deploys N fresh accounts, each pre-funded with `min_stake` STRK.
2. Each account calls `Staking::stake(...)` — `self.stakers.push(staker_address)` is executed N times. [2](#0-1) 
3. Each account calls `unstake_intent()`, waits for `exit_wait_window`, then calls `unstake_action()`. Funds are returned. The `staker_info` record is deleted, but the address remains in `self.stakers`. [6](#0-5) 
4. Attacker repeats steps 1–3 with new addresses to grow the Vec further (capital is recycled each cycle).
5. Any call to `get_stakers(epoch_id)` now iterates over all N dead entries, each requiring at least one storage read. As N grows, the function's gas cost grows linearly and eventually exceeds the block gas limit. [7](#0-6) 
6. The consensus layer can no longer retrieve the validator set, causing a permanent DoS on consensus participation.

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

**File:** src/staking/staking.cairo (L2464-2475)
```text
        fn is_staker_active(
            self: @ContractState, staker_address: ContractAddress, epoch_id: Epoch,
        ) -> bool {
            match self.staker_info.read(staker_address) {
                VInternalStakerInfo::V1(staker_info_v1) => {
                    // `intent_epoch` is zero if the intent exists from before V3.
                    staker_info_v1.unstake_time.is_none()
                        || epoch_id < self.staker_unstake_intent_epoch.read(staker_address)
                },
                _ => false,
            }
        }
```
