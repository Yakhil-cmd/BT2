### Title
Missing Caller Validation in `exit_delegation_pool_action` Enables Forced Pool Member Exit — (File: `src/pool/pool.cairo`)

### Summary
`exit_delegation_pool_action` in `pool.cairo` accepts an arbitrary `pool_member` address but never checks that `get_caller_address() == pool_member`. Any unprivileged address can invoke this function against any pool member once the unpool window has elapsed, permanently finalizing an exit the member may have intended to cancel.

### Finding Description
The external report's vulnerability class is **missing/insufficient caller-origin validation** — functions that should restrict who may invoke them instead accept calls from any origin. The direct analog here is `exit_delegation_pool_action`. [1](#0-0) 

The function signature is:

```cairo
fn exit_delegation_pool_action(
    ref self: ContractState, pool_member: ContractAddress,
) -> Amount {
```

The only guards present are:
1. `pool_member_info` must exist (panics if not).
2. `unpool_time` must be set (panics if no intent).
3. `Time::now() >= unpool_time` (panics if window not elapsed). [2](#0-1) 

There is **no** `assert!(get_caller_address() == pool_member, ...)` guard. Compare this with every other sensitive pool function:

- `add_to_delegation_pool` — checks `caller == pool_member || caller == reward_address` [3](#0-2) 
- `claim_rewards` — checks `caller == pool_member || caller == reward_address` [4](#0-3) 
- `enter_delegation_pool_from_staking_contract` — checks `assert_caller_is_staking_contract()` [5](#0-4) 

`exit_delegation_pool_action` is the sole public state-mutating function with no caller restriction.

Critically, a pool member **can** cancel a pending exit intent at any time — including after `unpool_time` — by calling `exit_delegation_pool_intent(amount: 0)`, which sets `unpool_time = None` and `unpool_amount = 0`: [6](#0-5) 

Because `exit_delegation_pool_action` has no caller guard, an attacker can front-run the cancellation transaction and permanently finalize the exit before the member can cancel.

### Impact Explanation
Once `exit_delegation_pool_action` is forced:
- `unpool_amount` is transferred to `pool_member` (not the attacker).
- `unpool_time` and `unpool_amount` are cleared.
- The member's balance in the epoch trace was already reduced when they called `exit_delegation_pool_intent`. [7](#0-6) 

The pool member cannot recover their staking position without re-entering the pool, incurring a K-epoch delay before their stake becomes active again and losing any rewards that would have accrued during that gap. This constitutes **griefing with damage to users** — the attacker gains nothing, but the victim loses their active staking position and accrued future yield.

This matches: **Medium — Griefing with no profit motive but damage to users or protocol.**

### Likelihood Explanation
- The attack requires no privileged role, no leaked key, and no external dependency.
- Any unprivileged address can call `exit_delegation_pool_action` for any pool member once `unpool_time` has elapsed.
- Front-running a cancellation transaction is feasible on Starknet (sequencer ordering is observable).
- The attacker bears only gas cost.

### Recommendation
Add a caller restriction to `exit_delegation_pool_action` consistent with the pattern used in `claim_rewards` and `add_to_delegation_pool`:

```cairo
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

### Proof of Concept
1. Pool member Alice calls `exit_delegation_pool_intent(amount: X)`. Her balance in the trace is reduced by `X`; `unpool_time` is set to `T`.
2. Alice changes her mind and submits `exit_delegation_pool_intent(amount: 0)` to cancel.
3. Attacker Bob observes Alice's cancellation in the mempool (after `T` has elapsed) and submits `exit_delegation_pool_action(pool_member: Alice)` with higher priority.
4. Bob's transaction executes first: Alice's `unpool_amount` is transferred to her, `unpool_time` is cleared.
5. Alice's cancellation now fails (`MISSING_UNDELEGATE_INTENT`) because `unpool_time` is already `None`.
6. Alice has lost her staking position for `X` tokens and must re-enter the pool, waiting K epochs before her stake is active again.

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

**File:** src/pool/pool.cairo (L267-274)
```text
            // Edit the pool member to reflect the removal intent, and write to storage.
            if amount.is_zero() {
                pool_member_info.unpool_time = Option::None;
            } else {
                pool_member_info.unpool_time = Option::Some(unpool_time);
            }
            pool_member_info.unpool_amount = amount;
            let new_delegated_stake = total_amount - amount;
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

**File:** src/pool/pool.cairo (L436-436)
```text
            self.assert_caller_is_staking_contract();
```
