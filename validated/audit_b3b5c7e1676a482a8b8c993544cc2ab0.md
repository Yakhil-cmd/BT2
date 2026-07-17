### Title
Wrong Receiver Identity Used in `validate_delegate_action` for Inner-Action Validation — (`File: runtime/runtime/src/action_validation.rs`)

---

### Summary

In `validate_delegate_action`, the pre-`FixDelegatedDeterministicStateInit` code path passes `receiver` — the **outer transaction's `receiver_id`**, which equals the delegate action's `sender_id` — as the `receiver_id` argument to `validate_actions_with_mode` instead of `delegate_action.receiver_id()`, the **actual target of the inner actions**. This is the exact nearcore analog of the BendDAO H-08 pattern: when a relayer (privileged third party) acts on behalf of a user, the system uses the relayer-side identity for a critical lookup/check instead of the user-side identity.

---

### Finding Description

`validate_delegate_action` is called during both transaction validation and receipt validation. It receives two distinct account IDs:

- `receiver` — the outer transaction's `receiver_id`, which is the account on which the `DelegateAction` is being processed (i.e., the `sender_id` of the delegate action).
- `delegate_action.receiver_id()` — the actual target account for the inner actions.

In the buggy code path (protocol versions before `FixDelegatedDeterministicStateInit`):

```rust
// runtime/runtime/src/action_validation.rs
fn validate_delegate_action(
    limit_config: &LimitConfig,
    delegate_action: VersionedDelegateActionRef<'_>,
    receiver: &AccountId,          // outer tx receiver = delegate sender's account
    current_protocol_version: ProtocolVersion,
    mode: ValidateReceiptMode,
) -> Result<(), ActionsValidationError> {
    let actions = delegate_action.get_actions();
    let inner_receiver =
        if ProtocolFeature::FixDelegatedDeterministicStateInit.enabled(current_protocol_version) {
            delegate_action.receiver_id()   // CORRECT
        } else {
            receiver                        // BUG: outer tx receiver, not inner action receiver
        };
    validate_actions_with_mode(limit_config, &actions, inner_receiver, ...)?;
    Ok(())
}
```

`validate_actions_with_mode` calls `validate_deterministic_state_init` for any `DeterministicStateInit` inner action:

```rust
// runtime/runtime/src/action_validation.rs
fn validate_deterministic_state_init(
    limit_config: &LimitConfig,
    action: &DeterministicStateInitAction,
    receiver_id: &AccountId,   // receives the wrong id in the buggy path
) -> Result<(), ActionsValidationError> {
    let derived_id = derive_near_deterministic_account_id(&action.state_init);
    if derived_id != *receiver_id {          // checked against outer tx receiver, not inner receiver
        return Err(ActionsValidationError::InvalidDeterministicStateInitReceiver { ... });
    }
    ...
}
```

The exact corrupted value is `inner_receiver`: it is `receiver` (the delegate action sender's named account, e.g. `alice.near`) instead of `delegate_action.receiver_id()` (the deterministic account, e.g. `0s69284a5453e7be5632b28b6a01baecf6c12c156d`).

---

### Impact Explanation

Two concrete consequences flow from the wrong identity:

1. **Legitimate meta-transactions with `DeterministicStateInit` are always rejected.** A user who wants to deploy a deterministic account via a relayer submits a `DelegateAction` where `sender_id = alice.near` and `receiver_id = 0s<hash>`. The outer tx receiver is `alice.near`. The check `derive(state_init) == alice.near` always fails, so the transaction is rejected at the pre-inclusion validation stage. The feature is completely unusable through meta-transactions.

2. **An attacker can craft a transaction that passes initial validation but targets the wrong deterministic account.** If the attacker controls a deterministic account `det_b = derive(state_init_b)` and uses it as the outer tx receiver, the check `derive(state_init_b) == det_b` passes. The inner delegate action can then target `det_a` (a different deterministic account). The exploit tx is admitted to the pool and the relayer pays gas; the error is only caught later at receipt validation (`NewReceiptValidationError::ActionsValidation::InvalidDeterministicStateInitReceiver`), wasting the relayer's gas with no recourse.

The broken invariant is: **the receiver identity used to validate inner actions of a `DelegateAction` must be the inner action's receiver, not the outer transaction's receiver.**

---

### Likelihood Explanation

Any unprivileged user can submit a `SignedTransaction` containing a `DelegateAction` wrapping a `DeterministicStateInit`. No validator, node-admin, or trusted-service privilege is required. The attacker-controlled fields are the `state_init` content and the `receiver_id` of the delegate action, both of which are free-form user inputs accepted by the JSON-RPC endpoint. The bug is reachable on every node running a protocol version below `FixDelegatedDeterministicStateInit`.

---

### Recommendation

The fix is already present in the codebase behind the `FixDelegatedDeterministicStateInit` protocol feature flag. The corrected path uses `delegate_action.receiver_id()` as `inner_receiver`. Nodes should upgrade to the protocol version that enables this feature. The dual-path code can be simplified once the old protocol version is no longer supported.

---

### Proof of Concept

The existing test `try_meta_tx_deterministic_receiver_exploit` in `test-loop-tests/src/tests/deterministic_account_id.rs` demonstrates both effects:

- At `fix_version - 1`: the exploit tx passes initial tx validation (wrong receiver accepted), then fails at receipt validation.
- At `fix_version`: the exploit tx is correctly rejected at tx validation.

The root cause is at: [1](#0-0) 

The downstream check that receives the wrong identity: [2](#0-1) 

The test confirming the pre-fix behavior (exploit passes tx validation, fails at receipt): [3](#0-2) 

The test confirming the post-fix behavior (exploit rejected at tx validation): [4](#0-3)

### Citations

**File:** runtime/runtime/src/action_validation.rs (L180-207)
```rust
fn validate_delegate_action(
    limit_config: &LimitConfig,
    delegate_action: VersionedDelegateActionRef<'_>,
    receiver: &AccountId,
    current_protocol_version: ProtocolVersion,
    mode: ValidateReceiptMode,
) -> Result<(), ActionsValidationError> {
    let actions = delegate_action.get_actions();
    let inner_receiver =
        if ProtocolFeature::FixDelegatedDeterministicStateInit.enabled(current_protocol_version) {
            // This is the correct receiver id to use for the check.
            delegate_action.receiver_id()
        } else {
            // This is a bug fixed with `FixDelegatedDeterministicStateInit` that
            // validated against the wrong id. This makes it impossible to
            // initialize deterministic accounts from meta transactions.
            // The bug cannot be abused, if someone crafts a state init that passes
            // validation here, it will fail when it is checked as incoming receipt.
            receiver
        };
    validate_actions_with_mode(
        limit_config,
        &actions,
        inner_receiver,
        current_protocol_version,
        mode,
    )?;
    Ok(())
```

**File:** runtime/runtime/src/action_validation.rs (L413-427)
```rust
fn validate_deterministic_state_init(
    limit_config: &LimitConfig,
    action: &DeterministicStateInitAction,
    receiver_id: &AccountId,
) -> Result<(), ActionsValidationError> {
    validate_global_contract_identifier(action.state_init.code())?;

    let derived_id = derive_near_deterministic_account_id(&action.state_init);

    if derived_id != *receiver_id {
        return Err(ActionsValidationError::InvalidDeterministicStateInitReceiver {
            derived_id,
            receiver_id: receiver_id.clone(),
        });
    }
```

**File:** test-loop-tests/src/tests/deterministic_account_id.rs (L136-157)
```rust
#[test]
// Pins to a pre-spice protocol version; skipped under the spice feature.
#[cfg_attr(feature = "protocol_feature_spice", ignore)]
fn test_deterministic_state_init_meta_tx_receiver_check_pre_fix() {
    let fix_version = ProtocolFeature::FixDelegatedDeterministicStateInit.protocol_version();
    let outcome = try_meta_tx_deterministic_receiver_exploit(fix_version - 1)
        .expect("without the fix, exploit tx passes initial tx validation");

    assert_matches!(
        outcome.status,
        FinalExecutionStatus::Failure(TxExecutionError::ActionError(ActionError {
            kind: ActionErrorKind::NewReceiptValidationError(
                ReceiptValidationError::ActionsValidation(
                    ActionsValidationError::InvalidDeterministicStateInitReceiver { .. }
                )
            ),
            ..
        })),
        "expected InvalidDeterministicStateInitReceiver in NewReceiptValidationError, got: {:?}",
        outcome.status
    );
}
```

**File:** test-loop-tests/src/tests/deterministic_account_id.rs (L159-175)
```rust
/// With `FixDelegatedDeterministicStateInit` in place, the exploit should
/// already be caught at the first tx validation.
#[test]
// Pins to a pre-spice protocol version; skipped under the spice feature.
#[cfg_attr(feature = "protocol_feature_spice", ignore)]
fn test_deterministic_state_init_meta_tx_receiver_check() {
    let fix_version = ProtocolFeature::FixDelegatedDeterministicStateInit.protocol_version();
    let err = try_meta_tx_deterministic_receiver_exploit(fix_version)
        .expect_err("exploit tx must be rejected at tx validation with the fix");
    assert_matches!(
        err,
        InvalidTxError::ActionsValidation(
            ActionsValidationError::InvalidDeterministicStateInitReceiver { .. }
        ),
        "wrong error: {err:?}"
    );
}
```
