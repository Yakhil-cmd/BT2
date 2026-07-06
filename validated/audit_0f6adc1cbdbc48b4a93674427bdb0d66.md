### Title
Attacker Can Frontrun `exit_delegation_pool_action` to Permanently Block Pool Member from Switching Delegation Pools - (File: src/pool/pool.cairo)

### Summary

`exit_delegation_pool_action` in the pool contract has no access control — any address can execute it for any pool member. A pool member who has signaled exit intent and is waiting to call `switch_delegation_pool` can be griefed by an attacker who calls `exit_delegation_pool_action` first, clearing the `unpool_time` state that `switch_delegation_pool` requires. This forces the pool member to restart the full 1-week exit window cycle indefinitely.

### Finding Description

`exit_delegation_pool_action` in `src/pool/pool.cairo` is callable by any address with no caller restriction:

```rust
fn exit_delegation_pool_action(
    ref self: ContractState, pool_member: ContractAddress,
) -> Amount {
    let mut pool_member_info = self.internal_pool_member_info(:pool_member);
    let unpool_time = pool_member_info
        .unpool_time
        .expect_with_err(GenericError::MISSING_UNDELEGATE_INTENT);
    assert!(Time::now() >= unpool_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);
    // ... clears unpool_time and unpool_amount, transfers funds to pool_member
``` [1](#0-0) 

`switch_delegation_pool`, however, requires `unpool_time.is_some()` as a hard precondition:

```rust
fn switch_delegation_pool(...) {
    assert!(
        pool_member_info.unpool_time.is_some(),
        "{}",
        GenericError::MISSING_UNDELEGATE_INTENT,
    );
``` [2](#0-1) 

The spec explicitly confirms both behaviors — `exit_delegation_pool_action` access control is "Any address can execute" and `switch_delegation_pool` precondition is "Pool member (caller) is in exit window": [3](#0-2) [4](#0-3) 

**Attack path:**

1. Pool member calls `exit_delegation_pool_intent(amount)` — sets `unpool_time` and `unpool_amount`, removes amount from staked balance.
2. Pool member waits for the 1-week exit window to expire.
3. Pool member submits `switch_delegation_pool(to_staker, to_pool, amount)` to the mempool.
4. Attacker observes the pending transaction and frontruns it by calling `exit_delegation_pool_action(pool_member)`.
5. `exit_delegation_pool_action` clears `unpool_time = None` and `unpool_amount = 0`, and transfers funds back to the pool member.
6. Pool member's `switch_delegation_pool` call reverts with `MISSING_UNDELEGATE_INTENT`.
7. Pool member must restart the entire 1-week exit window cycle. The attacker can repeat this indefinitely at only gas cost. [1](#0-0) 

### Impact Explanation

The pool member is permanently prevented from atomically switching delegation pools as long as the attacker is willing to pay gas. Each attempt requires the pool member to wait another full exit window (1 week by default, up to 12 weeks). During each cycle, the pool member's funds are removed from the staked balance (earning no rewards) for the entire exit window duration. The attacker has no cost beyond gas; the victim suffers repeated reward loss and is effectively locked out of the `switch_delegation_pool` flow. This is griefing with no profit motive but concrete, repeatable damage to users.

Impact: **Medium — Griefing with no profit motive but damage to users or protocol.**

### Likelihood Explanation

The attack requires only a standard unprivileged address and knowledge of the pool member's pending `switch_delegation_pool` transaction (observable via mempool or emitted `PoolMemberExitIntent` events). The cost to the attacker is a single gas payment per grief cycle. The victim must pay the full exit window cost (1 week of lost rewards) per cycle. Likelihood is **High** for any pool member who is publicly known to be switching pools.

### Recommendation

Restrict `exit_delegation_pool_action` so that only the pool member or their registered `reward_address` can execute it:

```rust
fn exit_delegation_pool_action(
    ref self: ContractState, pool_member: ContractAddress,
) -> Amount {
    let caller = get_caller_address();
    let pool_member_info = self.internal_pool_member_info(:pool_member);
    assert!(
        caller == pool_member || caller == pool_member_info.reward_address,
        "{}",
        Error::UNAUTHORIZED_CALLER,
    );
    // ... rest of function
```

This mirrors the access control pattern already used in `add_to_delegation_pool` and `claim_rewards`. [5](#0-4) 

### Proof of Concept

```
// Pseudocode (Starknet Foundry style)
// 1. Pool member enters pool and signals exit intent
cheat_caller_address_once(pool_contract, pool_member);
pool.exit_delegation_pool_intent(amount);

// 2. Advance time past exit window
start_cheat_block_timestamp_global(Time::now() + exit_wait_window + 1);

// 3. Attacker frontruns pool member's switch_delegation_pool call
// Attacker is any unprivileged address
cheat_caller_address_once(pool_contract, attacker);
pool.exit_delegation_pool_action(pool_member); // succeeds, clears unpool_time

// 4. Pool member's switch attempt now fails
cheat_caller_address_once(pool_contract, pool_member);
let result = pool_safe.switch_delegation_pool(to_staker, to_pool, amount);
// Panics with: "MISSING_UNDELEGATE_INTENT"
assert_panic_with_error(result, GenericError::MISSING_UNDELEGATE_INTENT.describe());
``` [6](#0-5)

### Citations

**File:** src/pool/pool.cairo (L227-232)
```text
            let caller_address = get_caller_address();
            assert!(
                caller_address == pool_member || caller_address == pool_member_info.reward_address,
                "{}",
                Error::CALLER_CANNOT_ADD_TO_POOL,
            );
```

**File:** src/pool/pool.cairo (L295-333)
```text
        fn exit_delegation_pool_action(
            ref self: ContractState, pool_member: ContractAddress,
        ) -> Amount {
            // Asserts.
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let unpool_time = pool_member_info
                .unpool_time
                .expect_with_err(GenericError::MISSING_UNDELEGATE_INTENT);
            assert!(Time::now() >= unpool_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);

            // Emit event.
            self
                .emit(
                    Events::PoolMemberExitAction {
                        pool_member, unpool_amount: pool_member_info.unpool_amount,
                    },
                );

            // Perform removal action in the staking contract, receiving funds if needed.
            // Note that if the intent was done after the staker was removed (unstake_action),
            // the funds will already be in the pool contract, and the following call will do
            // nothing.
            let staking_pool_dispatcher = self.staking_pool_dispatcher.read();
            staking_pool_dispatcher
                .remove_from_delegation_pool_action(identifier: pool_member.into());

            let unpool_amount = pool_member_info.unpool_amount;
            pool_member_info.unpool_amount = Zero::zero();
            pool_member_info.unpool_time = Option::None;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer delegated amount to the pool member.
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());

            unpool_amount
        }
```

**File:** src/pool/pool.cairo (L379-429)
```text
        fn switch_delegation_pool(
            ref self: ContractState,
            to_staker: ContractAddress,
            to_pool: ContractAddress,
            amount: Amount,
        ) -> Amount {
            // Asserts.
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            assert!(
                pool_member_info.unpool_time.is_some(),
                "{}",
                GenericError::MISSING_UNDELEGATE_INTENT,
            );
            assert!(amount <= pool_member_info.unpool_amount, "{}", GenericError::AMOUNT_TOO_HIGH);
            let reward_address = pool_member_info.reward_address;

            // Update pool_member_info and write to storage.
            pool_member_info.unpool_amount -= amount;
            if pool_member_info.unpool_amount.is_zero() {
                // unpool_amount is zero, clear unpool_time.
                pool_member_info.unpool_time = Option::None;
            }
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Serialize the switch pool data and invoke the staking contract to switch pool.
            let switch_pool_data = SwitchPoolData { pool_member, reward_address };
            let mut serialized_data = array![];
            switch_pool_data.serialize(ref output: serialized_data);
            self
                .staking_pool_dispatcher
                .read()
                .switch_staking_delegation_pool(
                    :to_staker,
                    :to_pool,
                    switched_amount: amount,
                    data: serialized_data.span(),
                    identifier: pool_member.into(),
                );

            // Emit event.
            self
                .emit(
                    Events::SwitchDelegationPool {
                        pool_member, new_delegation_pool: to_pool, amount,
                    },
                );

            pool_member_info.unpool_amount
        }
```

**File:** docs/spec.md (L1999-2001)
```markdown
3. Staking contract is unpaused.
#### access control <!-- omit from toc -->
Any address can execute.
```

**File:** docs/spec.md (L2054-2056)
```markdown
#### pre-condition <!-- omit from toc -->
1. `amount` is not zero.
2. Pool member (caller) is in exit window.
```
