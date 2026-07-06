### Title
Unrestricted `exit_delegation_pool_action` Allows Any Caller to Force Unwanted Pool Exits, Blocking Pool Switches - (File: src/pool/pool.cairo)

### Summary
The `exit_delegation_pool_action` function in the Pool contract accepts a `pool_member: ContractAddress` parameter and performs no caller validation. Any unprivileged address can call it for any pool member whose exit window has elapsed, forcibly clearing the member's exit-intent state and returning their funds. This can be used to grief pool members who intend to switch delegation pools, permanently blocking the switch until the victim re-enters and waits through the full exit window again.

### Finding Description
`exit_delegation_pool_action` (pool.cairo lines 295–333) takes an arbitrary `pool_member` address and executes the full exit flow for that member with no check that `get_caller_address() == pool_member` (or their reward address):

```cairo
fn exit_delegation_pool_action(
    ref self: ContractState, pool_member: ContractAddress,
) -> Amount {
    let mut pool_member_info = self.internal_pool_member_info(:pool_member);
    let unpool_time = pool_member_info
        .unpool_time
        .expect_with_err(GenericError::MISSING_UNDELEGATE_INTENT);
    assert!(Time::now() >= unpool_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);
    // ... clears unpool_amount / unpool_time, transfers funds to pool_member
    token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());
``` [1](#0-0) 

The function clears `pool_member_info.unpool_time` and `pool_member_info.unpool_amount` and transfers the staked tokens back to `pool_member`. There is no `get_caller_address()` guard anywhere in the function. [2](#0-1) 

The `switch_delegation_pool` function, by contrast, requires `pool_member_info.unpool_time.is_some()` as a hard precondition:

```cairo
assert!(
    pool_member_info.unpool_time.is_some(),
    "{}",
    GenericError::MISSING_UNDELEGATE_INTENT,
);
``` [3](#0-2) 

Once an attacker calls `exit_delegation_pool_action` on a victim's address, `unpool_time` is `None`, and any pending `switch_delegation_pool` call by the victim will revert with `MISSING_UNDELEGATE_INTENT`.

### Impact Explanation
A pool member who wants to move their stake to a different staker's pool must:
1. Call `exit_delegation_pool_intent(amount)` — starts the exit window.
2. Wait for the full exit window to elapse.
3. Call `switch_delegation_pool(to_staker, to_pool, amount)` — atomically moves stake.

An attacker can monitor the chain and, as soon as the exit window elapses (step 2 complete), call `exit_delegation_pool_action(victim)` before the victim's step-3 transaction lands. This:
- Clears the victim's `unpool_time` / `unpool_amount`.
- Returns the victim's tokens to their address.
- Forces the victim to re-enter the pool from scratch and wait through the entire exit window again.

The attacker can repeat this indefinitely, permanently preventing the victim from ever successfully switching pools. The victim loses delegation rewards for every forced re-entry cycle and pays repeated gas costs. This constitutes **griefing with no profit motive but concrete, repeatable damage to users**.

### Likelihood Explanation
The attack requires no privileged role, no leaked key, and no external dependency. Any address can call `exit_delegation_pool_action` at any time after the victim's exit window elapses. The attacker only needs to watch on-chain state (or the mempool) for pool members whose `unpool_time` has passed and who have not yet called `switch_delegation_pool`. This is a realistic, low-cost, repeatable attack.

### Recommendation
Add a caller restriction identical to the one used in `claim_rewards` and `add_to_delegation_pool`:

```cairo
fn exit_delegation_pool_action(
    ref self: ContractState, pool_member: ContractAddress,
) -> Amount {
    let caller_address = get_caller_address();
    let mut pool_member_info = self.internal_pool_member_info(:pool_member);
    assert!(
        caller_address == pool_member || caller_address == pool_member_info.reward_address,
        "{}",
        Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
    );
    // ... rest of function unchanged
```

This mirrors the access pattern already enforced in `claim_rewards`: [4](#0-3) 

### Proof of Concept
1. Alice (pool member) calls `exit_delegation_pool_intent(amount)` — `unpool_time` is set to `now + exit_window`.
2. The exit window elapses; Alice's `unpool_time` is now in the past.
3. Alice submits a transaction calling `switch_delegation_pool(to_staker, to_pool, amount)`.
4. Attacker Bob observes Alice's pending transaction (or simply polls on-chain state) and front-runs it by calling `exit_delegation_pool_action(alice_address)`.
5. Bob's call succeeds: Alice's `unpool_amount` is transferred to Alice, and `unpool_time = None`.
6. Alice's `switch_delegation_pool` reverts: `MISSING_UNDELEGATE_INTENT` because `unpool_time.is_none()`.
7. Alice must call `enter_delegation_pool` again, wait through the full exit window, and retry — Bob can repeat step 4 indefinitely. [1](#0-0)

### Citations

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

**File:** src/pool/pool.cairo (L338-344)
```text
            let caller_address = get_caller_address();
            let reward_address = pool_member_info.reward_address;
            assert!(
                caller_address == pool_member || caller_address == reward_address,
                "{}",
                Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );
```

**File:** src/pool/pool.cairo (L389-393)
```text
            assert!(
                pool_member_info.unpool_time.is_some(),
                "{}",
                GenericError::MISSING_UNDELEGATE_INTENT,
            );
```
