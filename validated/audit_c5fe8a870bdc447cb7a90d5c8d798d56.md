### Title
Reward Address Can Contribute Funds But Cannot Initiate Exit — Permanent Fund Loss for Reward Address - (File: `src/staking/staking.cairo`, `src/pool/pool.cairo`)

### Summary
`increase_stake` in `staking.cairo` and `add_to_delegation_pool` in `pool.cairo` both permit the **reward address** to contribute funds from its own balance into the staker's or pool member's position. However, the corresponding exit functions — `unstake_intent` and `exit_delegation_pool_intent` — restrict the caller strictly to the staker or pool member themselves. This access-control asymmetry mirrors the external report exactly: a party that is permitted to *enter* a state is not permitted to *exit* it. When the staker or pool member eventually exits, the contributed funds flow to them, not back to the reward address.

---

### Finding Description

**Entry — broader access control:**

In `staking.cairo`, `increase_stake` allows either the staker or the reward address to transfer funds from their own balance into the staker's position:

```cairo
assert!(
    caller_address == staker_address || caller_address == staker_info.reward_address,
    "{}",
    Error::CALLER_CANNOT_INCREASE_STAKE,
);
token_dispatcher.checked_transfer_from(
    sender: caller_address,          // may be reward_address
    recipient: staking_contract_address,
    amount: amount.into(),
);
``` [1](#0-0) 

In `pool.cairo`, `add_to_delegation_pool` similarly allows either the pool member or the reward address to contribute:

```cairo
assert!(
    caller_address == pool_member || caller_address == pool_member_info.reward_address,
    "{}",
    Error::CALLER_CANNOT_ADD_TO_POOL,
);
transfer_from_delegator(pool_member: caller_address, :amount, :token_dispatcher);
``` [2](#0-1) 

**Exit — narrower access control (only the staker / pool member):**

`unstake_intent` derives the staker address exclusively from `get_caller_address()`, so only the staker can call it:

```cairo
fn unstake_intent(ref self: ContractState) -> Timestamp {
    self.general_prerequisites();
    let staker_address = get_caller_address();
    ...
}
``` [3](#0-2) 

`exit_delegation_pool_intent` does the same — only the pool member can call it:

```cairo
fn exit_delegation_pool_intent(ref self: ContractState, amount: Amount) {
    let pool_member = get_caller_address();
    ...
}
``` [4](#0-3) 

**Funds flow to staker / pool member on exit, not back to reward address:**

`unstake_action` transfers to `staker_address`: [5](#0-4) 

`exit_delegation_pool_action` transfers to `pool_member`: [6](#0-5) 

The reward address has no path to recover the funds it contributed.

---

### Impact Explanation

The reward address's contributed principal is permanently redirected to the staker or pool member upon exit. The reward address cannot initiate `unstake_intent` or `exit_delegation_pool_intent` to reclaim its own funds. This constitutes a **permanent, irrecoverable loss of principal** for the reward address — matching the "Temporary/Permanent freezing of funds" impact category (High) or at minimum "damage to users" (Medium).

---

### Likelihood Explanation

The reward address is explicitly permitted to call `increase_stake` and `add_to_delegation_pool` — this is a documented, intended feature (spec section on `increase_stake` access control: "Only the staker address or rewards address"). [7](#0-6) 

A reward address that is a separate entity (e.g., a treasury contract, a different EOA, or a yield-compounding contract) may reasonably call these functions expecting to be able to withdraw its contribution later. The asymmetry is not documented as a restriction, making accidental fund loss realistic.

---

### Recommendation

Either:
1. **Restrict `increase_stake` and `add_to_delegation_pool`** to only the staker/pool member (removing the reward address permission), so no third party can contribute irrecoverable funds; or
2. **Allow the reward address to initiate exit** in `unstake_intent` and `exit_delegation_pool_intent`, mirroring the symmetric access control already present in `claim_rewards` (which allows both staker and reward address).

The symmetric fix for `unstake_intent` would be:
```diff
- let staker_address = get_caller_address();
+ let caller = get_caller_address();
+ let staker_address = if caller == staker_info.reward_address { staker_address_param } else { caller };
```

---

### Proof of Concept

**Staking contract path:**
1. Staker `A` calls `stake(reward_address: R, ...)` — `R` is a separate address.
2. `R` calls `increase_stake(staker_address: A, amount: X)` — `X` tokens are transferred **from R's balance** into the staking contract, credited to `A`'s position.
3. `A` calls `unstake_intent()` — only `A` can do this; `R` cannot.
4. After the exit window, anyone calls `unstake_action(A)` — `A` receives all staked funds including `R`'s `X` tokens.
5. `R` has permanently lost `X` tokens with no recourse.

**Pool contract path:**
1. Pool member `P` enters a delegation pool with reward address `R`.
2. `R` calls `add_to_delegation_pool(pool_member: P, amount: Y)` — `Y` tokens transferred from `R`.
3. `P` calls `exit_delegation_pool_intent(amount: total)` — `R` cannot call this.
4. After the exit window, `exit_delegation_pool_action(P)` sends all funds to `P`.
5. `R` has permanently lost `Y` tokens. [8](#0-7) [9](#0-8)

### Citations

**File:** src/staking/staking.cairo (L368-409)
```text
        fn increase_stake(
            ref self: ContractState, staker_address: ContractAddress, amount: Amount,
        ) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let caller_address = get_caller_address();
            let staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
            assert!(
                caller_address == staker_address || caller_address == staker_info.reward_address,
                "{}",
                Error::CALLER_CANNOT_INCREASE_STAKE,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let normalized_amount = NormalizedAmountTrait::from_strk_native_amount(:amount);

            // Transfer funds from caller (which is either the staker or their reward address).
            let staking_contract_address = get_contract_address();
            let token_dispatcher = strk_token_dispatcher();
            token_dispatcher
                .checked_transfer_from(
                    sender: caller_address,
                    recipient: staking_contract_address,
                    amount: amount.into(),
                );

            // Update staker's staked amount, and total stake.
            let (normalized_old_self_stake, normalized_new_self_stake) = self
                .increase_staker_own_amount(:staker_address, amount: normalized_amount);

            // Emit events.
            let new_self_stake = normalized_new_self_stake.to_strk_native_amount();
            self
                .emit(
                    Events::StakeOwnBalanceChanged {
                        staker_address,
                        old_self_stake: normalized_old_self_stake.to_strk_native_amount(),
                        new_self_stake,
                    },
                );
            new_self_stake
        }
```

**File:** src/staking/staking.cairo (L433-437)
```text
        fn unstake_intent(ref self: ContractState) -> Timestamp {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_address = get_caller_address();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

**File:** src/staking/staking.cairo (L504-506)
```text
            // Return stake to staker.
            token_dispatcher
                .checked_transfer(recipient: staker_address, amount: staker_amount.into());
```

**File:** src/pool/pool.cairo (L221-254)
```text
        fn add_to_delegation_pool(
            ref self: ContractState, pool_member: ContractAddress, amount: Amount,
        ) -> Amount {
            // Asserts.
            self.assert_staker_is_active();
            let pool_member_info = self.internal_pool_member_info(:pool_member);
            let caller_address = get_caller_address();
            assert!(
                caller_address == pool_member || caller_address == pool_member_info.reward_address,
                "{}",
                Error::CALLER_CANNOT_ADD_TO_POOL,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);

            // Transfer funds from the delegator to the staking contract.
            let token_dispatcher = self.token_dispatcher.read();
            let staker_address = self.staker_address.read();
            transfer_from_delegator(pool_member: caller_address, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);

            // Update the pool member's balance checkpoint.
            let old_delegated_stake = self.increase_member_balance(:pool_member, :amount);
            let new_delegated_stake = old_delegated_stake + amount;

            // Emit events.
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake, new_delegated_stake,
                    },
                );

            new_delegated_stake
        }
```

**File:** src/pool/pool.cairo (L256-259)
```text
        fn exit_delegation_pool_intent(ref self: ContractState, amount: Amount) {
            // Asserts.
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
```

**File:** src/pool/pool.cairo (L329-330)
```text
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());
```

**File:** docs/spec.md (L643-644)
```markdown
#### access control <!-- omit from toc -->
Only the staker address or rewards address for which the change is requested for.
```
