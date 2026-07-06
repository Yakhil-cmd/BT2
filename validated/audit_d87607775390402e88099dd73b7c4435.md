### Title
Unbounded `stakers` Vec Iteration in `get_stakers` Enables Unbounded Gas Consumption DoS - (File: src/staking/staking.cairo)

### Summary
The `stakers` storage Vec in the Staking contract grows by one entry every time a new staker calls `stake()`, and entries are **never removed** even after a staker fully unstakes. The `get_stakers` function in `StakingConsensusImpl` iterates over the **entire** Vec on every call. Because any unprivileged address can call `stake()` with the minimum stake amount, an attacker (or organic protocol growth) can make `get_stakers` prohibitively expensive, eventually causing it to exceed execution limits and permanently DoS the consensus layer's ability to retrieve the validator set.

### Finding Description

**Root cause — unbounded Vec growth:**

Every call to `stake()` unconditionally appends the new staker address to `self.stakers`: [1](#0-0) 

There is no corresponding removal when a staker calls `unstake_intent` / `unstake_action`. Stakers who have fully exited remain in the Vec forever.

**Root cause — full-range iteration:**

`get_stakers` (part of `IStakingConsensus`, callable by any address) iterates over every element of `self.stakers` with `into_iter_full_range()`: [2](#0-1) 

For each element it performs at minimum one storage read (`staker_address_ptr.read()`) plus a call to `is_staker_active`, and for active stakers it additionally calls `get_staker_staking_power_at_epoch`, `get_public_key_at_epoch`, and `get_peer_id_at_epoch`. The cost is strictly O(|stakers|) with no upper bound.

**Attacker-controlled entry path:**

`stake()` is a public, permissionless function. Any address that holds the minimum STRK stake amount can call it, adding one permanent entry to the Vec. The `assert_staker_address_not_reused` guard only prevents the *same* address from staking twice; a script using distinct addresses faces no such restriction. [3](#0-2) 

**No cap exists:** The interface comment for `add_token` explicitly warns about unbounded complexity and instructs the token admin to enforce a limit: [4](#0-3) 

No analogous warning or enforcement exists for the `stakers` Vec.

### Impact Explanation

`get_stakers` is the function the consensus layer calls to obtain the full validator set for a given epoch (access control: "Any address"). If the Vec grows large enough that `get_stakers` exceeds Starknet's execution-step limit, the call reverts. The consensus layer can no longer retrieve the validator set, permanently freezing the protocol's ability to assign attestation duties and distribute rewards. This constitutes **unbounded gas consumption** leading to a DoS of core consensus functionality — matching the Medium impact tier ("Griefing with no profit motive but damage to users or protocol; Unbounded gas consumption").

### Likelihood Explanation

**Low.** Each attacker address must hold and lock the minimum STRK stake, making a large-scale attack capital-intensive. However, organic protocol growth (many legitimate stakers joining and leaving over time) produces the same effect without any malicious intent, since exited stakers are never pruned from the Vec. The risk therefore increases monotonically with protocol adoption.

### Recommendation

1. **Prune on exit**: Remove the staker's address from `self.stakers` when `unstake_action` is called (e.g., swap-and-pop pattern on the Vec).
2. **Alternatively, cap the Vec**: Enforce a maximum number of registered stakers (analogous to the "limit to 50 pools" recommendation in the reference report).
3. **Lazy iteration**: Store only *active* stakers in the Vec and move exited stakers to a separate archive structure that `get_stakers` does not iterate.

### Proof of Concept

```
// Attacker script (pseudocode)
for i in 0..N:
    addr_i = fresh_address()
    strk.transfer(addr_i, min_stake)
    staking.stake(
        reward_address: addr_i,
        operational_address: addr_i,
        amount: min_stake,
        pool_enabled: false,
        commission: 0
    )  // appends addr_i to self.stakers permanently

// After N iterations:
staking.get_stakers(current_epoch)
// → iterates N entries, each requiring multiple storage reads
// → at sufficiently large N, execution steps exceed the Starknet limit
// → call reverts; consensus layer cannot retrieve validator set
```

Each `stake()` call is independent and permissionless. The `stakers` Vec length after the loop is exactly N, and `get_stakers` must read all N entries regardless of how many are still active.

### Citations

**File:** src/staking/staking.cairo (L301-349)
```text
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
            let normalized_amount = NormalizedAmountTrait::from_strk_native_amount(:amount);

            // Transfer funds from staker. Sufficient approvals is a pre-condition.
            let staking_contract = get_contract_address();
            let token_dispatcher = strk_token_dispatcher();
            token_dispatcher
                .checked_transfer_from(
                    sender: staker_address, recipient: staking_contract, amount: amount.into(),
                );

            self
                .initialize_staker_own_balance_trace(
                    :staker_address, own_balance: normalized_amount,
                );

            // Create the record for the staker.
            self
                .staker_info
                .write(
                    staker_address,
                    VInternalStakerInfoTrait::new_latest(:reward_address, :operational_address),
                );

            // Update the operational address mapping, which is a 1 to 1 mapping.
            self.operational_address_to_staker_address.write(operational_address, staker_address);

            // Update total stake.
            self.add_to_total_stake(token_address: STRK_TOKEN_ADDRESS, amount: normalized_amount);

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

**File:** src/staking/interface.cairo (L262-273)
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
    /// 2. Token decimals are validated once upon addition (expected to be 8).
    /// Subsequent changes to the token's decimals are not supported and may lead to issues.
    fn add_token(ref self: TContractState, token_address: ContractAddress);
```
