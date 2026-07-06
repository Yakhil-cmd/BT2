### Title
Pause Mechanism Blocks Staker and Delegator Withdrawals, Causing Temporary Fund Freeze - (File: `src/staking/staking.cairo`)

---

### Summary

The Starknet Staking contract implements a global pause mechanism via an `is_paused` flag. The `general_prerequisites()` guard is applied uniformly to **all** state-changing functions, including the withdrawal path (`unstake_intent`, `unstake_action`, `remove_from_delegation_pool_intent`, `remove_from_delegation_pool_action`). When a security agent pauses the contract for any security reason, stakers and delegators are completely unable to initiate or complete withdrawals of their principal funds.

---

### Finding Description

The staking contract exposes a `pause()` function callable by the security agent role. Internally, every user-facing function begins with a call to `general_prerequisites()`, which asserts the contract is not paused. This includes the two-phase exit functions for both stakers and delegators.

**Staker withdrawal path** — both phases check the pause flag:

- `unstake_intent` (line 433–435): calls `self.general_prerequisites()` before any logic executes.
- `unstake_action` (line 483–485): calls `self.general_prerequisites()` before any logic executes. [1](#0-0) [2](#0-1) 

**Delegator withdrawal path** — the staking-side pool functions that the Pool contract calls are also gated:

- `remove_from_delegation_pool_intent` — blocked when paused (confirmed by test at line 258–269).
- `remove_from_delegation_pool_action` — blocked when paused (confirmed by test at line 271–281). [3](#0-2) 

The Pool contract's `exit_delegation_pool_intent` and `exit_delegation_pool_action` both propagate `CONTRACT_IS_PAUSED` errors because they call into the staking contract, which is paused. [4](#0-3) 

The pause/unpause implementation itself: [5](#0-4) 

The `IStakingPause` interface documents that pausing "prevents any state changes (balance changes, staker settings, etc.)" — confirming the design intentionally blocks all state changes, including withdrawals. [6](#0-5) 

---

### Impact Explanation

When the staking contract is paused:

1. **Stakers** cannot call `unstake_intent()` to begin their exit window, nor `unstake_action()` to retrieve their principal STRK after the window expires — even if the exit window had already elapsed before the pause.
2. **Delegators** cannot call `exit_delegation_pool_intent()` or `exit_delegation_pool_action()` on their Pool contract to recover delegated tokens.

All principal funds (staked STRK and delegated tokens) are frozen for the duration of the pause. The exit wait window is up to the configured `MAX_EXIT_WAIT_WINDOW`; if the contract remains paused, users cannot recover funds at all during that period. This matches the allowed impact: **High — Temporary freezing of funds**.

---

### Likelihood Explanation

The security agent role can pause the contract unilaterally at any time. A pause is a routine security response (e.g., to a suspected exploit or bridge anomaly). The pause is not time-bounded in the contract — it persists until a security admin calls `unpause()`. There is no on-chain guarantee of when or whether unpause occurs. Any legitimate pause event directly and immediately freezes all user withdrawals. Likelihood is **Medium-High** given that pauses are an expected operational event.

---

### Recommendation

Exempt the withdrawal-completion functions from the pause check. Specifically:

- `unstake_action` should be callable even when paused (funds are already committed to exit; the exit window has elapsed).
- `exit_delegation_pool_action` (and its underlying `remove_from_delegation_pool_action`) should similarly be exempt.

Optionally, `unstake_intent` and `exit_delegation_pool_intent` could also be exempted so users can at least begin their exit window during a pause. At minimum, the action (fund-return) phase must never be blocked.

---

### Proof of Concept

The existing test suite already demonstrates the freeze:

```
// src/staking/tests/pause_test.cairo, line 171-181
#[test]
#[should_panic(expected: "Contract is paused")]
fn test_unstake_action_when_paused() {
    ...
    staking_dispatcher.unstake_action(staker_address: DUMMY_ADDRESS);
}
``` [7](#0-6) 

Concrete scenario:

1. Staker calls `unstake_intent()` — exit window starts (e.g., 1 week).
2. Security agent calls `pause()` before the week elapses.
3. One week passes; the exit window has expired, but `unstake_action()` reverts with `"Contract is paused"`.
4. Staker's principal STRK is locked in the contract with no recourse until the security admin calls `unpause()`.

The same scenario applies to delegators via `exit_delegation_pool_action`. [8](#0-7) [9](#0-8)

### Citations

**File:** src/staking/staking.cairo (L433-436)
```text
        fn unstake_intent(ref self: ContractState) -> Timestamp {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let staker_address = get_caller_address();
```

**File:** src/staking/staking.cairo (L483-486)
```text
        fn unstake_action(ref self: ContractState, staker_address: ContractAddress) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let mut staker_info = self.internal_staker_info(:staker_address);
```

**File:** src/staking/staking.cairo (L1249-1267)
```text
    impl StakingPauseImpl of IStakingPause<ContractState> {
        fn pause(ref self: ContractState) {
            self.roles.only_security_agent();
            if self.is_paused() {
                return;
            }
            self.is_paused.write(true);
            self.emit(PauseEvents::Paused { account: get_caller_address() });
        }

        fn unpause(ref self: ContractState) {
            self.roles.only_security_admin();
            if !self.is_paused() {
                return;
            }
            self.is_paused.write(false);
            self.emit(PauseEvents::Unpaused { account: get_caller_address() });
        }
    }
```

**File:** src/staking/tests/pause_test.cairo (L171-181)
```text
#[test]
#[should_panic(expected: "Contract is paused")]
fn test_unstake_action_when_paused() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    pause_staking_contract(:cfg);
    let staking_dispatcher = IStakingDispatcher {
        contract_address: cfg.test_info.staking_contract,
    };
    staking_dispatcher.unstake_action(staker_address: DUMMY_ADDRESS);
}
```

**File:** src/staking/tests/pause_test.cairo (L256-281)
```text
#[test]
#[should_panic(expected: "Contract is paused")]
fn test_remove_from_delegation_pool_intent_when_paused() {
    let mut cfg: StakingInitConfig = Default::default();
    general_contract_system_deployment(ref :cfg);
    pause_staking_contract(:cfg);
    let staking_pool_dispatcher = IStakingPoolDispatcher {
        contract_address: cfg.test_info.staking_contract,
    };
    staking_pool_dispatcher
        .remove_from_delegation_pool_intent(
            staker_address: DUMMY_ADDRESS, identifier: DUMMY_IDENTIFIER, amount: 0,
        );
}

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

**File:** docs/spec.md (L1962-1999)
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
#### access control <!-- omit from toc -->
Only the pool member address for which the operation is requested for.
#### logic <!-- omit from toc -->
1. If staker is active, call [remove from delegation pool intent](#remove_from_delegation_pool_intent)
2. If `amount` is zero, remove request for intent (if exists).
3. If `amount` is not zero, set exit window timeout.
4. Update delegator's balance for curr_epoch + K.

### exit_delegation_pool_action
```rust
fn exit_delegation_pool_action(
    ref self: ContractState,
    pool_member: ContractAddress
) -> Amount
```
#### description <!-- omit from toc -->
Executes the intent to exit the stake if enough time have passed. Transfers the funds back to the pool member.
Return the amount of tokens transferred back to the pool member.
#### emits <!-- omit from toc -->
1. [Pool Member Exit Action](#pool-member-exit-action)
#### errors <!-- omit from toc -->
1. [POOL\_MEMBER\_DOES\_NOT\_EXIST](#pool_member_does_not_exist)
2. [MISSING\_UNDELEGATE\_INTENT](#missing_undelegate_intent)
3. [INTENT\_WINDOW\_NOT\_FINISHED](#intent_window_not_finished)
4. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
#### pre-condition <!-- omit from toc -->
1. Pool member exist and requested to unstake.
2. Enough time have passed from the delegation pool exit intent call.
3. Staking contract is unpaused.
```

**File:** src/staking/interface.cairo (L231-239)
```text
#[starknet::interface]
pub trait IStakingPause<TContractState> {
    /// Pause the staking contract.
    /// Pausing the staking contract prevents any state changes (balance changes, staker settings,
    /// etc.)
    fn pause(ref self: TContractState);
    /// Unpause the staking contract.
    fn unpause(ref self: TContractState);
}
```
