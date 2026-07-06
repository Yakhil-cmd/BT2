### Title
Unbounded Iteration Over Ever-Growing `stakers` Vec in `get_stakers()` Causes Unbounded Gas Consumption - (File: src/staking/staking.cairo)

### Summary
The `get_stakers()` function in `src/staking/staking.cairo` iterates over a `stakers` storage `Vec` that grows monotonically and is never pruned. Because unstaked stakers are explicitly never removed from this vector, the iteration cost grows without bound as the protocol accumulates historical stakers, eventually making the function prohibitively expensive or impossible to execute.

### Finding Description
The `stakers` storage field is declared with an explicit note that entries are never removed:

```
/// Vector of staker addresses.
/// **Note**: Stakers are not removed from this vector when they unstake.
stakers: Vec<ContractAddress>,
``` [1](#0-0) 

Every call to `stake()` appends to this Vec unconditionally:

```cairo
self.stakers.push(staker_address);
``` [2](#0-1) 

The `get_stakers()` function then iterates over the **entire** Vec on every call, performing multiple storage reads per entry (staker activity check, staking power calculation, public key lookup, peer ID lookup):

```cairo
for staker_address_ptr in self.stakers.into_iter_full_range() {
    let staker_address = staker_address_ptr.read();
    if !self.is_staker_active(:staker_address, :epoch_id) {
        continue;
    }
    let staking_power = self
        .get_staker_staking_power_at_epoch(...);
    ...
    let public_key = self.get_public_key_at_epoch(:staker_address, :epoch_id);
    let peer_id = self.get_peer_id_at_epoch(:staker_address, :epoch_id);
    stakers.append((staker_address, staking_power, public_key, peer_id));
}
``` [3](#0-2) 

Each iteration touches at minimum: the staker version map, the staker own balance trace, the staker delegated balance trace (per pool), the public key map, and the peer ID map — all storage reads. Inactive (unstaked) stakers are skipped with `continue` but still cost a storage read for the activity check.

### Impact Explanation
**Impact: Medium — Unbounded gas consumption.**

As the protocol accumulates stakers over time (each new staker permanently inflates the Vec), `get_stakers()` becomes progressively more expensive. Since `get_stakers()` is part of `IStakingConsensus` and is the mechanism by which the consensus layer retrieves the validator set for a given epoch, an inability to execute this function disrupts the protocol's ability to produce the validator committee. Even as a view/off-chain call, Starknet imposes execution resource limits; a sufficiently large Vec will cause the call to fail, preventing the consensus layer from obtaining the staker list.

### Likelihood Explanation
**Likelihood: High.**

Every `stake()` call by any unprivileged user permanently grows the Vec. There is no minimum barrier beyond `min_stake` to register as a staker. An adversary can register many staker addresses (each with `min_stake`) and immediately call `unstake_intent()` / `unstake_action()` to recover funds, leaving dead entries in the Vec forever. Even without adversarial behavior, organic protocol growth will continuously inflate the Vec. The cost grows linearly with the total number of historical stakers, not just active ones.

### Recommendation
1. **Remove stakers from the Vec on `unstake_action()`**, or use a separate active-staker set that is pruned on exit.
2. Alternatively, replace the `Vec` with a paginated or off-chain-indexed structure and add a `start_index` / `count` parameter to `get_stakers()` so callers can retrieve the list in bounded chunks across multiple calls.
3. At minimum, document the operational limit and add a governance-controlled maximum staker count.

### Proof of Concept
1. Deploy the staking contract.
2. Register N staker addresses (each with `min_stake` STRK), then call `unstake_intent()` + `unstake_action()` on each to recover funds. Each address remains permanently in `self.stakers`.
3. Call `get_stakers(epoch_id)`. Observe that execution cost scales linearly with N, regardless of how many stakers are currently active.
4. As N grows large enough to exceed Starknet's per-transaction or per-call execution resource limits, `get_stakers()` reverts, preventing the consensus layer from obtaining the validator set. [4](#0-3) [1](#0-0) [5](#0-4)

### Citations

**File:** src/staking/staking.cairo (L167-169)
```text
        /// Vector of staker addresses.
        /// **Note**: Stakers are not removed from this vector when they unstake.
        stakers: Vec<ContractAddress>,
```

**File:** src/staking/staking.cairo (L346-349)
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
