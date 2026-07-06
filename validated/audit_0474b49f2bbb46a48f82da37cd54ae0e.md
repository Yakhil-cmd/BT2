### Title
Monotonically Growing `stakers` Vec Causes Unbounded Gas in `get_stakers()` - (`src/staking/staking.cairo`)

### Summary

`get_stakers()` iterates over a `Vec<ContractAddress>` called `stakers` that is explicitly never pruned when stakers exit. Any unprivileged address can call `stake()` to append to this Vec. Over time the Vec grows without bound, and each call to `get_stakers()` performs multiple storage reads per entry, eventually exceeding Starknet's execution resource limits and making the consensus-layer staker enumeration permanently unavailable.

### Finding Description

The storage field `stakers` is declared with an explicit note that entries are never removed:

```
/// Vector of staker addresses.
/// **Note**: Stakers are not removed from this vector when they unstake.
stakers: Vec<ContractAddress>,
``` [1](#0-0) 

`get_stakers()` iterates over the **full range** of this Vec unconditionally:

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
``` [2](#0-1) 

For every entry — including all historical stakers who have long since unstaked — the loop performs:

1. `staker_address_ptr.read()` — 1 storage read (Vec slot)
2. `is_staker_active()` — reads `staker_info` + conditionally `staker_unstake_intent_epoch` (1–2 reads)
3. For active stakers: `get_staker_staking_power_at_epoch()` → `get_staker_total_strk_btc_balance_at_epoch()` → `get_staker_own_balance_at_epoch()` + one `get_staker_delegated_balance_at_epoch()` per pool (3+ reads)
4. `get_public_key_at_epoch()` — 1 read
5. `get_peer_id_at_epoch()` — 1 read [3](#0-2) 

`is_staker_active()` itself reads two storage slots per staker:

```cairo
fn is_staker_active(...) -> bool {
    match self.staker_info.read(staker_address) {
        VInternalStakerInfo::V1(staker_info_v1) => {
            staker_info_v1.unstake_time.is_none()
                || epoch_id < self.staker_unstake_intent_epoch.read(staker_address)
        },
        _ => false,
    }
}
``` [4](#0-3) 

Even for an exited staker (the common case after the protocol matures), the loop still reads the Vec slot and the `staker_info` map entry before it can `continue`. That is a minimum of **2 storage reads per historical staker** with no upper bound on the Vec length.

### Impact Explanation

`get_stakers()` is the function the consensus layer calls to enumerate all active validators for a given epoch. Its interface is `IStakingConsensus` and access is unrestricted ("Any address"): [5](#0-4) 

When the Vec grows large enough to exceed Starknet's per-call execution resource ceiling, every invocation of `get_stakers()` will fail. The consensus layer loses the ability to enumerate active validators, permanently breaking the epoch-based validator selection mechanism. This constitutes **unbounded gas consumption** leading to permanent unavailability of a critical protocol function — matching the allowed Medium impact: *"Griefing with no profit motive but damage to users or protocol; Unbounded gas consumption."*

### Likelihood Explanation

The Starknet staking protocol is designed for long-term operation with an open, permissionless `stake()` entry point. Every address that ever stakes is appended to `stakers` and never removed. On a live network with thousands of validators cycling in and out over months or years, the Vec will grow to tens of thousands of entries. This is not a theoretical edge case; it is the expected steady-state of the protocol.

### Recommendation

1. **Track active count separately.** Maintain a `active_staker_count: u32` counter incremented on `stake()` and decremented on `unstake_action()`. This allows O(1) checks without iterating the Vec.
2. **Compact the Vec or use a separate active set.** Maintain a second `active_stakers: Vec<ContractAddress>` that is pruned on `unstake_action()`, or use a swap-and-pop pattern on the existing Vec.
3. **Paginate `get_stakers()`.** Accept `offset` and `limit` parameters so callers can retrieve the staker list in bounded chunks.
4. **Cap staker registration.** If a hard cap is acceptable, enforce a maximum `stakers.len()` in `stake()`.

### Proof of Concept

```
// 1. N addresses each call stake() — each is appended to `stakers` Vec.
//    stakers.len() == N after this step.

// 2. All N addresses call unstake_intent() then unstake_action().
//    stakers.len() is still N (no removal).

// 3. M new addresses call stake() — stakers.len() == N + M.

// 4. get_stakers(epoch_id) iterates all N + M entries.
//    For each of the N exited stakers: 2 storage reads (Vec slot + staker_info).
//    For each of the M active stakers: ~6+ storage reads.
//    Total reads ≈ 2N + 6M.

// 5. With N large enough (e.g., tens of thousands of historical stakers),
//    the call exceeds Starknet's execution resource limit and reverts,
//    making get_stakers() permanently uncallable.
``` [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L167-169)
```text
        /// Vector of staker addresses.
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
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

**File:** src/staking/staking.cairo (L2388-2410)
```text
        fn get_staker_staking_power_at_epoch(
            self: @ContractState,
            staker_address: ContractAddress,
            epoch_id: Epoch,
            strk_total_stake: NormalizedAmount,
            btc_total_stake: NormalizedAmount,
        ) -> StakingPower {
            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            let (staker_strk_total_amount, staker_btc_total_amount) = self
                .get_staker_total_strk_btc_balance_at_epoch(
                    :staker_address, :staker_pool_info, :epoch_id,
                );
            if staker_strk_total_amount.is_zero() {
                return Zero::zero();
            }

            calculate_staker_total_staking_power(
                :staker_strk_total_amount,
                :staker_btc_total_amount,
                :strk_total_stake,
                :btc_total_stake,
            )
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

**File:** src/staking/interface.cairo (L108-124)
```text
#[starknet::interface]
pub trait IStakingConsensus<TContractState> {
    /// Returns (epoch_id, epoch_starting_block, epoch_length) for the current epoch.
    fn get_current_epoch_data(self: @TContractState) -> (Epoch, BlockNumber, u32);
    /// Returns a span of (staker_address, staking_power, Option<public_key>, Option<peer_id>)
    /// for all stakers for the given `epoch_id` (`curr_epoch <= epoch_id < curr_epoch + K`).
    /// **Note**: The staking power is the relative weight of the staker's stake
    /// out of the total stake, including pooled stake (STRK and BTC), multiplied by
    /// `STAKING_POWER_BASE_VALUE`.
    /// **Note**: Disregards stakers that either no staking power, which can be either new stakers
    /// or stakers that called `exit_intent`.
    /// **Note**: Calling this function in the same epoch as the upgrade to V3 may panic.
    /// This will occur if a new staker was added in that epoch before the upgrade.
    fn get_stakers(
        self: @TContractState, epoch_id: Epoch,
    ) -> Span<(ContractAddress, StakingPower, Option<PublicKey>, Option<PeerId>)>;
}
```
