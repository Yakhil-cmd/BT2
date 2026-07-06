### Title
Any Address Can Force `exit_delegation_pool_action` on a Pool Member Without Consent, Preventing Intent Cancellation - (File: `src/pool/pool.cairo`)

### Summary
`exit_delegation_pool_action` in `pool.cairo` performs a state-changing operation — clearing a pool member's exit intent and transferring their staked funds — without any caller authorization check. A pool member who has signaled exit intent can cancel it by calling `exit_delegation_pool_intent(0)`, but once the exit window elapses, any address can front-run that cancellation by calling `exit_delegation_pool_action`, permanently forcing the pool member out of the pool and causing them to forfeit future staking rewards.

### Finding Description
The `exit_delegation_pool_action` function accepts a `pool_member: ContractAddress` parameter and executes the exit for that member with no check that the caller is the pool member or any authorized party. The only guards are that the pool member has a pending intent and that the exit window has elapsed:

```cairo
fn exit_delegation_pool_action(
    ref self: ContractState, pool_member: ContractAddress,
) -> Amount {
    let mut pool_member_info = self.internal_pool_member_info(:pool_member);
    let unpool_time = pool_member_info
        .unpool_time
        .expect_with_err(GenericError::MISSING_UNDELEGATE_INTENT);
    assert!(Time::now() >= unpool_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);
    // ... clears intent, transfers funds to pool_member
```

The spec explicitly documents this as "Any address can execute" (`docs/spec.md` line 2001), but this design creates a griefing vector because the pool member retains the ability to cancel their intent at any time by calling `exit_delegation_pool_intent(0)`:

```cairo
fn exit_delegation_pool_intent(ref self: ContractState, amount: Amount) {
    ...
    if amount.is_zero() {
        pool_member_info.unpool_time = Option::None;
    }
    pool_member_info.unpool_amount = amount;
```

Once the exit window has elapsed, an attacker monitoring the mempool can front-run the pool member's cancellation transaction with `exit_delegation_pool_action`, irrevocably executing the exit. The pool member's `unpool_amount` and `unpool_time` are cleared, their staked tokens are transferred back to them, and their active delegation balance is zeroed — all without their consent at the moment of execution.

This is the direct analog of the `deleteToken` pattern: a state-deletion operation (clearing the pool member's active delegation) that proceeds without requiring the affected party's consent at execution time.

### Impact Explanation
**Medium — Griefing with no profit motive but damage to users or protocol.**

The pool member receives their staked tokens back (no direct theft), but:
- They are permanently removed from active delegation in the pool.
- They lose all future staking rewards they would have earned by staying.
- They must re-enter the pool via `add_to_delegation_pool` (incurring gas costs and a K-epoch delay before their balance takes effect).
- The attacker gains nothing financially; the sole purpose is to harm the pool member.

### Likelihood Explanation
**Low-Medium.** The attack requires:
1. The pool member to have called `exit_delegation_pool_intent` and then changed their mind after the exit window elapsed.
2. The attacker to monitor the mempool and successfully front-run the cancellation transaction.

On Starknet, mempool front-running is feasible. The exit window is at least one week (`DEFAULT_EXIT_WAIT_WINDOW`), giving the pool member time to cancel before the window expires — but once it expires, the race condition opens.

### Recommendation
Add a caller authorization check to `exit_delegation_pool_action`, restricting execution to the pool member themselves (or optionally their registered `reward_address`), consistent with the authorization pattern already applied to `exit_delegation_pool_intent`, `claim_rewards`, and `switch_delegation_pool`:

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

This mirrors the authorization pattern used in `add_to_delegation_pool` and `claim_rewards`.

### Proof of Concept
1. Pool member calls `exit_delegation_pool_intent(total_amount)` — signals full exit, balance moves to intent.
2. Exit window (`≥ 1 week`) elapses; `exit_delegation_pool_action` becomes callable.
3. Pool member reconsiders and submits `exit_delegation_pool_intent(0)` to cancel.
4. Attacker front-runs with `exit_delegation_pool_action(pool_member)`.
5. Pool member's intent is cleared, their tokens are transferred back to them, and their delegation balance is zeroed — they are out of the pool against their will.
6. Pool member must re-enter via `add_to_delegation_pool` and wait K epochs for their balance to take effect, losing all rewards during the gap.

**Root cause**: [1](#0-0) 

**Cancellation mechanism that can be front-run**: [2](#0-1) 

**Spec confirming the open access control**: [3](#0-2) 

**Funds transfer to pool member (no attacker gain)**: [4](#0-3)

### Citations

**File:** src/pool/pool.cairo (L256-278)
```text
        fn exit_delegation_pool_intent(ref self: ContractState, amount: Amount) {
            // Asserts.
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let old_delegated_stake = self.get_last_member_balance(:pool_member);
            let total_amount = old_delegated_stake + pool_member_info.unpool_amount;
            assert!(amount <= total_amount, "{}", GenericError::AMOUNT_TOO_HIGH);

            // Notify the staking contract of the removal intent.
            let unpool_time = self.undelegate_from_staking_contract_intent(:pool_member, :amount);

            // Edit the pool member to reflect the removal intent, and write to storage.
            if amount.is_zero() {
                pool_member_info.unpool_time = Option::None;
            } else {
                pool_member_info.unpool_time = Option::Some(unpool_time);
            }
            pool_member_info.unpool_amount = amount;
            let new_delegated_stake = total_amount - amount;
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Update the pool member's balance checkpoint.
            self.set_member_balance(:pool_member, amount: new_delegated_stake);
```

**File:** src/pool/pool.cairo (L295-303)
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
```

**File:** src/pool/pool.cairo (L321-331)
```text
            let unpool_amount = pool_member_info.unpool_amount;
            pool_member_info.unpool_amount = Zero::zero();
            pool_member_info.unpool_time = Option::None;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer delegated amount to the pool member.
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());

```

**File:** docs/spec.md (L1999-2004)
```markdown
3. Staking contract is unpaused.
#### access control <!-- omit from toc -->
Any address can execute.
#### logic <!-- omit from toc -->
1. [Remove from delegation pool action](#remove_from_delegation_pool_action).
2. Transfer funds to pool member.
```
