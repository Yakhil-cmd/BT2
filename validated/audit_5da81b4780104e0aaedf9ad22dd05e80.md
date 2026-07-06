### Title
Unbounded `self.stakers` Vec Growth Allows DoS of `get_stakers()` - (File: src/staking/staking.cairo)

### Summary

`get_stakers()` iterates over every address ever staked via `self.stakers.into_iter_full_range()` with no pagination. Because `stake()` permanently appends to `self.stakers` and `remove_staker()` never removes entries from it, an attacker can inflate the Vec by cycling through many addresses (stake → unstake_intent → unstake_action → repeat with new address), eventually causing `get_stakers()` to exceed Starknet's gas/step limits.

### Finding Description

In `src/staking/staking.cairo`, the `stake()` function appends every new staker address to a persistent `Vec`:

```
self.stakers.push(staker_address);   // line 348
``` [1](#0-0) 

When a staker exits via `unstake_action()`, the internal `remove_staker()` helper clears `staker_info`, the operational-address mapping, and commission fields — but it **never removes the address from `self.stakers`**: [2](#0-1) 

`get_stakers()` then iterates the **full range** of this ever-growing Vec on every call:

```cairo
for staker_address_ptr in self.stakers.into_iter_full_range() {
    let staker_address = staker_address_ptr.read();
    if !self.is_staker_active(:staker_address, :epoch_id) {
        continue;   // exited stakers still cost iteration gas
    }
    ...
}
``` [3](#0-2) 

There is no pagination, no upper-bound guard, and no mechanism to prune exited stakers from the Vec. The interface comment for `add_token` explicitly warns about unbounded loops over tokens and places the burden on an admin, but no equivalent protection exists for the stakers Vec. [4](#0-3) 

### Impact Explanation

`get_stakers()` is the consensus-layer view function that returns the full validator set for a given epoch. It is called by off-chain infrastructure (sequencer, consensus clients) and potentially on-chain. If the Vec grows large enough, every call will either:

- **On-chain**: exceed Starknet's per-transaction step limit, causing a hard revert.
- **Off-chain**: exceed RPC node timeout limits, making the validator set unreadable.

This permanently degrades the consensus mechanism's ability to read the active validator set, matching the allowed impact: **griefing with damage to the protocol / unbounded gas consumption (Medium)**.

### Likelihood Explanation

The attack requires the attacker to hold `min_stake` STRK tokens, but those tokens are **fully returned** after the exit wait window (~1 week). The only sustained cost is Starknet gas per cycle. Because `assert_staker_address_not_reused` prevents address reuse, each cycle requires a fresh address, but Starknet addresses are cheap to generate. A well-funded attacker can run this continuously, and even a moderately funded one can pre-load thousands of ghost entries before recovering their capital. [5](#0-4) 

### Recommendation

1. **Prune on exit**: In `remove_staker()`, swap-and-pop the exited address out of `self.stakers` (or use a separate active-staker set).
2. **Pagination**: Add `offset` / `limit` parameters to `get_stakers()` so callers can page through results.
3. **Active-set index**: Maintain a separate, compacted Vec of currently-active stakers that is updated on stake/unstake, and iterate only that.

### Proof of Concept

```
for i in 0..N:
    addr_i = fresh_address()
    approve(staking, min_stake, from=addr_i)
    stake(amount=min_stake, ..., from=addr_i)       // self.stakers.push(addr_i)
    unstake_intent(from=addr_i)
    wait(exit_wait_window)
    unstake_action(addr_i)                          // STRK returned; addr_i stays in Vec
// After N iterations, get_stakers() iterates N dead entries + live stakers
// At sufficient N, get_stakers() hits the step limit and reverts
``` [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L303-317)
```text
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

**File:** src/staking/interface.cairo (L262-270)
```text
pub trait IStakingTokenManager<TContractState> {
    /// Add a new token to the staking contract.
    ///
    /// **Important notes:**
    /// 1. This function should be called only a limited number of times.
    /// Adding too many tokens can lead to unbounded complexity and potential performance issues.
    /// The token set is intended to remain fixed and small, ensuring all loops over it are safely
    /// bounded.
    /// It is the token admin's responsibility to enforce this token limit.
```
