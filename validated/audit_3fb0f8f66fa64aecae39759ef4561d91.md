### Title
Unbounded `stakers` Vector Growth Allows Griefing of `get_stakers()` via Permanent Address Accumulation - (File: `src/staking/staking.cairo`)

### Summary
The `stakers` storage vector in `Staking.cairo` grows monotonically: every call to `stake()` appends the caller's address, and `unstake_action()` never removes it. The `get_stakers()` function iterates over the **full range** of this vector on every call. An unprivileged attacker can register thousands of staker addresses at minimum stake, immediately unstake to recover principal (paying only gas), and permanently bloat the vector, making `get_stakers()` prohibitively expensive or impossible to execute.

### Finding Description

**Root cause — unbounded push, no pop:**

`stake()` unconditionally appends the new staker address to `self.stakers`: [1](#0-0) 

`unstake_action()` clears the staker's pool list but **never removes the address from `self.stakers`**: [2](#0-1) 

`assert_staker_address_not_reused` prevents the same address from re-entering, so each address occupies exactly one permanent slot in the vector.

**Root cause — full-range iteration:**

`get_stakers()` iterates over every element ever pushed, including all exited stakers: [3](#0-2) 

Exited stakers are skipped via `is_staker_active()`, but they still consume gas during iteration. With N total historical stakers, every call to `get_stakers()` pays O(N) storage reads regardless of how many are currently active.

**`get_stakers()` is a consensus-critical function:**

The function is part of `IStakingConsensus` and is the mechanism by which the Starknet consensus layer determines the validator set and staking power for each epoch: [4](#0-3) [5](#0-4) 

### Impact Explanation

If `get_stakers()` exceeds the Starknet transaction step limit, the consensus layer cannot retrieve the validator set for the current or next epoch. This constitutes **unbounded gas consumption** and **griefing with damage to the protocol** — the consensus mechanism's ability to read validator assignments is permanently degraded. This matches the **Medium** impact tier: *Griefing with no profit motive but damage to users or protocol; Unbounded gas consumption*.

### Likelihood Explanation

The attack is cheap: the attacker only pays gas, not stake. After calling `unstake_intent()` and waiting the exit window, `unstake_action()` returns the full principal. The only recurring cost is transaction fees. With Starknet's low fees, flooding the vector with thousands of addresses is economically feasible. No privileged access is required — `stake()` is open to any address with `amount >= min_stake`. [6](#0-5) 

### Recommendation

1. **Compact the vector on exit**: When `unstake_action()` is called, swap-and-pop the staker's address from `self.stakers` (swap with the last element, then pop). This keeps the vector bounded to the number of *currently active* stakers.
2. **Alternatively, track a separate active-staker count** and enforce a cap, or use a set-like structure that supports O(1) removal.
3. **Add a maximum staker cap** as a short-term mitigation to bound the vector size.

### Proof of Concept

1. Deploy the staking contract with `min_stake = M`.
2. For `i` in `0..N` (e.g., N = 10,000):
   - Fund address `addr_i` with `M` STRK.
   - Call `staking.stake(reward_address, operational_address, M)` from `addr_i`.
   - Call `staking.unstake_intent()` from `addr_i`.
   - Advance time past `exit_wait_window`.
   - Call `staking.unstake_action(addr_i)` — principal returned, address stays in `self.stakers`.
3. After the loop, `self.stakers` contains N permanently dead entries.
4. Call `staking.get_stakers(epoch_id)` — the function must iterate all N entries, each requiring a storage read of `staker_info` (to check `is_staker_active`) plus additional reads for staking power. At sufficient N, the call exceeds the Starknet step limit and reverts. [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L288-317)
```text
        fn stake(
            ref self: ContractState,
            reward_address: ContractAddress,
            operational_address: ContractAddress,
            amount: Amount,
        ) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_address = get_caller_address();
            assert!(self.staker_info.read(staker_address).is_none(), "{}", Error::STAKER_EXISTS);
            assert!(
                self.operational_address_to_staker_address.read(operational_address).is_zero(),
                "{}",
                Error::OPERATIONAL_EXISTS,
            );
            self.assert_staker_address_not_reused(:staker_address);
            assert!(
                !self.does_token_exist(token_address: staker_address), "{}", Error::STAKER_IS_TOKEN,
            );
            assert!(
                !self.does_token_exist(token_address: reward_address),
                "{}",
                GenericError::REWARD_ADDRESS_IS_TOKEN,
            );
            assert!(
                !self.does_token_exist(token_address: operational_address),
                "{}",
                Error::OPERATIONAL_IS_TOKEN,
            );
            assert!(amount >= self.min_stake.read(), "{}", Error::AMOUNT_LESS_THAN_MIN_STAKE);
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

**File:** docs/spec.md (L1654-1673)
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
#### logic <!-- omit from toc -->
```
