### Title
Pool Contract `exit_delegation_pool_intent` Bypasses Staking Contract Pause When Staker Is Inactive - (File: src/pool/pool.cairo)

### Summary

The `Pool` contract's `exit_delegation_pool_intent` function does not enforce the staking contract's pause state when the associated staker has been removed (`staker_removed = true`). This allows pool members to start their exit-window countdown during a protocol pause, potentially enabling immediate fund withdrawal the moment the contract is unpaused.

### Finding Description

The staking contract exposes a `pause` / `unpause` mechanism. Every state-mutating function in the staking contract calls `general_prerequisites()`, which internally calls `assert_is_unpaused()`: [1](#0-0) 

Pool contract functions that call back into the staking contract inherit this protection indirectly. However, `exit_delegation_pool_intent` has two code paths:

1. **Staker active** → calls `remove_from_delegation_pool_intent` on the staking contract → pause check enforced.
2. **Staker inactive** (`staker_removed = true`) → the internal helper `undelegate_from_staking_contract_intent` short-circuits and returns `Time::now()` **without calling the staking contract at all**: [2](#0-1) 

The pool contract has no independent pause check. The spec explicitly lists `CONTRACT_IS_PAUSED` as a required error for `exit_delegation_pool_intent`: [3](#0-2) 

Because the inactive-staker path never touches the staking contract, the pause is silently bypassed.

### Impact Explanation

When the staking contract is paused (typically during a security incident), a pool member whose staker has already been removed can:

1. Call `exit_delegation_pool_intent` — succeeds because the inactive-staker path skips the staking contract entirely.
2. The `unpool_time` is set to `Time::now()`, starting the `DEFAULT_EXIT_WAIT_WINDOW` (1 week) countdown.
3. If the pause lasts longer than 1 week, the pool member can call `exit_delegation_pool_action` immediately upon unpausing, bypassing the intended security delay.

`exit_delegation_pool_action` does call `remove_from_delegation_pool_action` on the staking contract (which checks pause), so the actual token transfer is still blocked while paused. However, the exit-window timer runs during the pause, defeating the purpose of the freeze for this class of users.

This is a **Medium** impact: bypass of a manually administered security feature (the pause mechanism), causing damage to the protocol's security posture — directly analogous to the blacklist bypass in the reference report.

### Likelihood Explanation

- Requires only that a staker has called `unstake_action` (removing themselves), leaving pool members in the inactive-staker state.
- Any pool member in this state can trigger the bypass with a single unprivileged transaction.
- No special access, leaked keys, or external dependencies required.
- Likelihood is **Medium** — the inactive-staker state is a normal, expected protocol state.

### Recommendation

Add an explicit pause check at the top of `exit_delegation_pool_intent` in `pool.cairo`, mirroring the pattern used in the staking contract:

```cairo
fn exit_delegation_pool_intent(ref self: ContractState, amount: Amount) {
    // Add pause check:
    let staking_dispatcher = IStakingDispatcher {
        contract_address: self.staking_pool_dispatcher.contract_address.read(),
    };
    assert!(!staking_dispatcher.is_paused(), "{}", Error::CONTRACT_IS_PAUSED);
    // ... rest of function
}
```

Alternatively, the `undelegate_from_staking_contract_intent` helper can check the pause state before returning early on the inactive-staker path.

### Proof of Concept

1. Deploy staking + pool contracts.
2. Staker calls `stake`, then `set_open_for_delegation`.
3. Pool member calls `enter_delegation_pool`.
4. Staker calls `unstake_intent`, waits for exit window, calls `unstake_action` → pool contract receives funds, `staker_removed = true`.
5. Security agent calls `pause()` on the staking contract.
6. Pool member calls `exit_delegation_pool_intent(amount)` on the pool contract → **succeeds** (no revert), `unpool_time` is set to `Time::now()`.
7. After 1 week (while still paused), pool member calls `exit_delegation_pool_action` → reverts because staking contract is paused.
8. Security admin calls `unpause()` → pool member immediately calls `exit_delegation_pool_action` → **succeeds**, funds withdrawn with zero additional wait.

The exit-window security delay was fully consumed during the pause, defeating the intended freeze.

### Citations

**File:** src/staking/staking.cairo (L1657-1659)
```text
        fn assert_is_unpaused(self: @ContractState) {
            assert!(!self.is_paused(), "{}", Error::CONTRACT_IS_PAUSED);
        }
```

**File:** src/pool/pool.cairo (L637-656)
```text
        fn undelegate_from_staking_contract_intent(
            self: @ContractState, pool_member: ContractAddress, amount: Amount,
        ) -> Timestamp {
            if !self.is_staker_active() {
                // Don't allow intent if an intent is already in progress and the staker is erased.
                // Avoid the following flow:
                // 1. Member intent - moves member balance from the staker's `pool_amount` to
                // `UndelegateIntentKey`.
                // 2. Staker intent.
                // 3. Staker action - transfer the `pool_amount` from the staker to the pool
                // contract.
                // 4. Member intent - here it is no longer possible to move balance between the
                // `pool_amount` and the `UndelegateIntentKey`.
                assert!(
                    self.internal_pool_member_info(:pool_member).unpool_time.is_none(),
                    "{}",
                    Error::UNDELEGATE_IN_PROGRESS,
                );
                return Time::now();
            }
```

**File:** docs/spec.md (L1962-1970)
```markdown
1. [POOL\_MEMBER\_DOES\_NOT\_EXIST](#pool_member_does_not_exist)
2. [AMOUNT\_TOO\_HIGH](#amount_too_high)
3. [UNDELEGATE\_IN\_PROGRESS](#undelegate_in_progress)
4. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
#### pre-condition <!-- omit from toc -->
1. Pool member (caller) is listed in the contract.
2. `amount` is lower or equal to the total amount of the pool member (caller).
3. Pool member (caller) is not in an exit window or staker is active.
4. Staking contract is unpaused.
```
