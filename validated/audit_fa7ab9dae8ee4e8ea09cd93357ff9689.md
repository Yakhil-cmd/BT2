### Title
Pause Mechanism Blocks Stakers and Delegators from Withdrawing Funds After Exit Window Elapses - (File: `src/staking/staking.cairo`)

### Summary
The `general_prerequisites()` function in the `Staking` contract enforces a `CONTRACT_IS_PAUSED` check on every state-changing function, including `unstake_action` and `remove_from_delegation_pool_action`. When the contract is paused, stakers and delegators who have already completed the mandatory exit-wait window cannot execute their withdrawal actions, temporarily freezing their principal funds in the contract.

### Finding Description
The `general_prerequisites()` helper is called at the top of every mutating function in the staking contract. It asserts the contract is not paused before proceeding. This check is applied uniformly — it does not distinguish between operations that introduce new risk (e.g., `stake`, `increase_stake`) and operations that merely finalize a previously committed exit (e.g., `unstake_action`, `remove_from_delegation_pool_action`).

The affected withdrawal path is:

1. **Staker withdrawal**: `unstake_intent()` → wait `exit_wait_window` → `unstake_action()`. The `unstake_action` calls `general_prerequisites()` first, reverting with `"Contract is paused"` if the contract is paused.

2. **Delegator withdrawal**: `exit_delegation_pool_intent()` → wait `exit_wait_window` → `exit_delegation_pool_action()` (pool) → `remove_from_delegation_pool_action()` (staking). The staking contract's `remove_from_delegation_pool_action` calls `general_prerequisites()` at line 1115, reverting with `"Contract is paused"`.

The pause is confirmed to block both paths by the test suite:

- `test_unstake_action_when_paused` — `#[should_panic(expected: "Contract is paused")]`
- `test_remove_from_delegation_pool_action_when_paused` — `#[should_panic(expected: "Contract is paused")]`

The spec explicitly lists `CONTRACT_IS_PAUSED` as an error for `unstake_action` and `remove_from_delegation_pool_action`, confirming this is the implemented behavior.

### Impact Explanation
Any staker or delegator who has already submitted an exit intent and waited through the full `exit_wait_window` (up to 12 weeks per `MAX_EXIT_WAIT_WINDOW`) cannot retrieve their principal tokens while the contract is paused. The funds remain locked in the staking contract with no alternative withdrawal path. This constitutes **temporary freezing of funds** — a valid High impact per the allowed scope.

### Likelihood Explanation
The security agent can pause the contract at any time for legitimate operational reasons (security incident response, upgrade preparation, etc.). There is no minimum pause duration enforced. A pause of any non-trivial duration during which users have matured exit intents directly triggers the freeze. The scenario is realistic and requires no adversarial intent from the security agent — a routine pause is sufficient.

### Recommendation
Exempt `unstake_action` and `remove_from_delegation_pool_action` from the `general_prerequisites()` pause check. These functions only finalize a previously registered intent and transfer funds that have already been removed from the total staking power. They introduce no new protocol risk when executed during a pause. The pause check should be restricted to functions that create new obligations (e.g., `stake`, `increase_stake`, `enter_delegation_pool`).

### Proof of Concept

1. Staker calls `unstake_intent()` — exit window starts.
2. Staker waits the full `exit_wait_window` (e.g., 1 week default).
3. Security agent calls `pause()` on the staking contract.
4. Staker calls `unstake_action(staker_address)` — transaction reverts with `"Contract is paused"`.
5. Staker's principal STRK tokens remain locked in the staking contract with no recourse until the security admin calls `unpause()`.

The same sequence applies to a delegator calling `exit_delegation_pool_action` after a completed `exit_delegation_pool_intent`.

---

**Root cause**: `general_prerequisites()` in `src/staking/staking.cairo` applies the pause check unconditionally to all mutating functions. [1](#0-0) 

**Staking spec confirming `CONTRACT_IS_PAUSED` blocks `unstake_action`**: [2](#0-1) 

**Staking spec confirming `CONTRACT_IS_PAUSED` blocks `remove_from_delegation_pool_action`**: [3](#0-2) 

**Pool spec confirming `CONTRACT_IS_PAUSED` blocks `exit_delegation_pool_action`**: [4](#0-3) 

**Pause tests confirming the revert behavior**: [5](#0-4) [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L1113-1116)
```text
        fn remove_from_delegation_pool_action(ref self: ContractState, identifier: felt252) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let pool_contract = get_caller_address();
```

**File:** docs/spec.md (L691-699)
```markdown
#### errors <!-- omit from toc -->
1. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
2. [STAKER\_NOT\_EXISTS](#staker_not_exists)
3. [MISSING\_UNSTAKE\_INTENT](#missing_unstake_intent)
4. [INTENT\_WINDOW\_NOT\_FINISHED](#intent_window_not_finished)
5. [UNEXPECTED\_BALANCE](#unexpected_balance)
6. [STAKER\_ALREADY\_REMOVED](#staker_already_removed)
#### pre-condition <!-- omit from toc -->
1. Staking contract is unpaused.
```

**File:** docs/spec.md (L811-823)
```markdown
#### errors <!-- omit from toc -->
1. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
2. [INVALID\_UNDELEGATE\_INTENT\_VALUE](#invalid_undelegate_intent_value)
3. [INTENT\_WINDOW\_NOT\_FINISHED](#intent_window_not_finished)
#### pre-condition <!-- omit from toc -->
1. Staking contract is unpaused.
2. Removal intent request with the given `identifier` have been sent before.
3. Enough time have passed since the intent request.
#### access control <!-- omit from toc -->
Any address can execute.
#### logic <!-- omit from toc -->
1. Transfer funds from staking contract to pool contract.
2. Remove intent from staker's list.
```

**File:** docs/spec.md (L1991-1999)
```markdown
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
