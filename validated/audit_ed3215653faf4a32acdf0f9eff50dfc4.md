### Title
Pool Member Funds Frozen When Staking Contract Is Paused After Staker Removal - (`src/pool/pool.cairo`)

### Summary

`Pool.exit_delegation_pool_action` unconditionally calls `Staking.remove_from_delegation_pool_action` on the staking contract, which enforces a pause check via `general_prerequisites()` **before** checking whether the intent amount is zero. When the staking contract is paused after a staker has already been removed via `unstake_action` (at which point the delegated funds are already sitting in the pool contract), pool members are permanently blocked from withdrawing their own funds until governance unpauses the contract — even though the staking contract call would be a no-op.

---

### Finding Description

The pool contract's `exit_delegation_pool_action` function always calls `staking.remove_from_delegation_pool_action` regardless of whether the staker is still active: [1](#0-0) 

The developer comment on lines 313–316 explicitly acknowledges the case where the staker has already been removed: *"if the intent was done after the staker was removed (unstake_action), the funds will already be in the pool contract, and the following call will do nothing."* This comment signals the developer's intent that the call is safe to make as a no-op in that state.

However, on the staking contract side, `remove_from_delegation_pool_action` calls `general_prerequisites()` **first**, before the zero-amount early-return guard: [2](#0-1) 

`general_prerequisites()` enforces the pause check. When the staking contract is paused, it reverts unconditionally — even when the intent amount is zero and the call would have been a no-op.

The pause mechanism is confirmed to block `remove_from_delegation_pool_action`: [3](#0-2) 

The full vulnerable state machine is:

1. Pool member calls `exit_delegation_pool_intent(amount)` after the staker has already been removed via `unstake_action`. Per the spec, when the staker is not active, the pool contract does **not** call `staking.remove_from_delegation_pool_intent` — it only sets the local exit window. The staking contract therefore has no intent record (amount = zero) for this pool member.
2. The exit wait window elapses.
3. The security agent pauses the staking contract.
4. Pool member calls `exit_delegation_pool_action()` → pool calls `staking.remove_from_delegation_pool_action()` → `general_prerequisites()` reverts with `"Contract is paused"`.
5. Pool member's funds are locked in the pool contract with no path to withdrawal until governance unpauses.

The spec confirms `exit_delegation_pool_action` pre-condition 3 is "Staking contract is unpaused": [4](#0-3) 

This is inconsistent with the developer's own comment that the staking contract call "will do nothing" in the post-staker-removal case — the pause check makes it do something harmful (revert) instead.

---

### Impact Explanation

**Temporary freezing of funds (High).**

Pool members who have completed the exit intent flow after their staker was removed cannot retrieve their tokens from the pool contract while the staking contract is paused. The funds are physically present in the pool contract but inaccessible. Recovery requires governance to unpause the staking contract. This creates a dependency on governance action for users to exit — exactly the pattern the external report identified as dangerous.

---

### Likelihood Explanation

**Medium-High.** The security agent can pause the staking contract at any time (e.g., in response to an incident). Stakers with active delegation pools are common. The scenario where a staker exits (`unstake_action`) while pool members are still in the exit window is a normal operational sequence. The pause window could last hours or days, during which all affected pool members are frozen.

---

### Recommendation

Move the `general_prerequisites()` call in `remove_from_delegation_pool_action` to after the zero-amount guard, so that a no-op call does not revert when the contract is paused:

```cairo
fn remove_from_delegation_pool_action(ref self: ContractState, identifier: felt252) {
    let pool_contract = get_caller_address();
    let undelegate_intent_key = UndelegateIntentKey { pool_contract, identifier };
    let undelegate_intent = self.get_pool_exit_intent(:undelegate_intent_key);
    if undelegate_intent.amount.is_zero() {
        return; // No-op: skip pause check entirely
    }
    // Prerequisites and asserts only when there is actual work to do.
    self.general_prerequisites();
    ...
}
```

Alternatively, `exit_delegation_pool_action` in the pool contract could check whether the staker has been removed and skip the call to the staking contract entirely in that case.

---

### Proof of Concept

**State**: Staker has called `unstake_action` (pool contract holds delegated funds). Pool member subsequently called `exit_delegation_pool_intent`. Exit window has elapsed. Security agent pauses the staking contract.

**Call trace**:
```
pool_member → Pool.exit_delegation_pool_action(pool_member)
  → checks unpool_time: OK (window elapsed)
  → staking.remove_from_delegation_pool_action(identifier: pool_member.into())
      → self.general_prerequisites()   ← REVERTS: "Contract is paused"
```

The staking contract's intent record for this pool member has amount = zero (because the staker was already removed and funds transferred to the pool). The `general_prerequisites()` check fires before the zero-amount guard at line 1119, causing a revert that would not occur if the order were reversed. [5](#0-4) [6](#0-5)

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

**File:** src/staking/staking.cairo (L1113-1121)
```text
        fn remove_from_delegation_pool_action(ref self: ContractState, identifier: felt252) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let pool_contract = get_caller_address();
            let undelegate_intent_key = UndelegateIntentKey { pool_contract, identifier };
            let undelegate_intent = self.get_pool_exit_intent(:undelegate_intent_key);
            if undelegate_intent.amount.is_zero() {
                return;
            }
```

**File:** src/staking/tests/pause_test.cairo (L271-281)
```text
#[test]
#[should_panic(expected: "Contract is paused")]
fn test_remove_from_delegation_pool_action_when_paused() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    pause_staking_contract(:cfg);
    let staking_pool_dispatcher = IStakingPoolDispatcher {
        contract_address: cfg.test_info.staking_contract,
    };
    staking_pool_dispatcher.remove_from_delegation_pool_action(identifier: DUMMY_IDENTIFIER);
}
```

**File:** docs/spec.md (L1994-1999)
```markdown
3. [INTENT\_WINDOW\_NOT\_FINISHED](#intent_window_not_finished)
4. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
#### pre-condition <!-- omit from toc -->
1. Pool member exist and requested to unstake.
2. Enough time have passed from the delegation pool exit intent call.
3. Staking contract is unpaused.
```
