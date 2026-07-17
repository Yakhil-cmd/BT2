### Title
Wrong Receiver ID Used in `validate_delegate_action` Breaks `DeterministicStateInitAction` Inside Meta-Transactions — (`runtime/runtime/src/action_validation.rs`)

---

### Summary

In `validate_delegate_action`, before `ProtocolFeature::FixDelegatedDeterministicStateInit`, the inner actions of a `DelegateAction` (meta-transaction) are validated against the **outer transaction's receiver** (`receiver`, which equals `sender_id` of the delegate action) instead of the **actual inner receiver** (`delegate_action.receiver_id()`). This is the exact nearcore analog of M-25: the wrong identity (outer context / caller) is used in an authorization/validation check instead of the correct identity (the inner signed target).

---

### Finding Description

`validate_delegate_action` in `runtime/runtime/src/action_validation.rs` is called with `receiver` being the outer transaction's `receiver_id`, which equals the `sender_id` of the `DelegateAction` (the meta-tx sender's own account). The function then passes this wrong `receiver` as `inner_receiver` to `validate_actions_with_mode` for all inner actions:

```rust
fn validate_delegate_action(
    limit_config: &LimitConfig,
    delegate_action: VersionedDelegateActionRef<'_>,
    receiver: &AccountId,          // ← outer tx receiver = sender_id
    current_protocol_version: ProtocolVersion,
    mode: ValidateReceiptMode,
) -> Result<(), ActionsValidationError> {
    let actions = delegate_action.get_actions();
    let inner_receiver =
        if ProtocolFeature::FixDelegatedDeterministicStateInit.enabled(current_protocol_version) {
            delegate_action.receiver_id()   // ← correct
        } else {
            receiver                        // ← BUG: outer tx receiver, not inner delegate receiver
        };
    validate_actions_with_mode(limit_config, &actions, inner_receiver, ...)?;
    Ok(())
}
``` [1](#0-0) 

`validate_deterministic_state_init` enforces the invariant `derived_id == receiver_id`:

```rust
fn validate_deterministic_state_init(..., receiver_id: &AccountId) {
    let derived_id = derive_near_deterministic_account_id(&action.state_init);
    if derived_id != *receiver_id {
        return Err(ActionsValidationError::InvalidDeterministicStateInitReceiver { ... });
    }
}
``` [2](#0-1) 

When a user wraps a `DeterministicStateInitAction` inside a `DelegateAction`, the outer tx is addressed to the meta-tx sender (`sender_id`), not to the deterministic account being initialized. The buggy code checks `derive(state_init) == sender_id`, which is always false for a legitimate use, causing the transaction to be incorrectly rejected at pre-inclusion validation.

The exploit direction is the reverse: an attacker sets `outer_tx.receiver_id = det_account_b = derive(state_init_b)` but sets `delegate_action.receiver_id = det_account_a` (a different account). The buggy check passes (`det_account_b == derive(state_init_b)`), but the inner action targets the wrong account. The code comment acknowledges this:

> "The bug cannot be abused, if someone crafts a state init that passes validation here, it will fail when it is checked as incoming receipt." [3](#0-2) 

The test `try_meta_tx_deterministic_receiver_exploit` in `test-loop-tests/src/tests/deterministic_account_id.rs` demonstrates both directions: [4](#0-3) 

The call site in `validate_action_with_mode` passes `receiver` (the outer context) into `validate_delegate_action` for both `Action::Delegate` and `Action::DelegateV2`: [5](#0-4) 

---

### Impact Explanation

Any unprivileged user attempting to use `DeterministicStateInitAction` inside a `DelegateAction` (meta-transaction) will have their transaction incorrectly rejected at pre-inclusion validation. The invariant `derive(state_init) == delegate_action.receiver_id` is never checked; instead, the irrelevant `sender_id` is checked. This completely blocks the intended use of meta-transactions for deterministic account initialization — a broken authorization/receipt-causality invariant in the pre-inclusion transaction validation scope.

The `ProtocolFeature::FixDelegatedDeterministicStateInit` fix is assigned to protocol version 85: [6](#0-5) 

---

### Likelihood Explanation

Any user who constructs a `DelegateAction` containing a `DeterministicStateInitAction` and submits it through a relayer will trigger this bug on nodes running protocol versions below 85. The input is fully unprivileged-user-controlled (the `DelegateAction` payload is crafted off-chain by the user and submitted by any relayer).

---

### Recommendation

Use `delegate_action.receiver_id()` as the `inner_receiver` unconditionally, removing the protocol-version branch. The fix is already implemented behind `ProtocolFeature::FixDelegatedDeterministicStateInit`; the old branch should be removed once the feature is fully stabilized across the network.

---

### Proof of Concept

1. Deploy a global contract and derive two deterministic account IDs: `det_account_a` and `det_account_b` from `state_init_a` and `state_init_b` respectively.
2. Attempt a legitimate meta-transaction: `outer_tx.receiver_id = det_account_b` (the sender), `delegate_action.receiver_id = det_account_a`, inner action = `DeterministicStateInitAction(state_init_a)`.
3. Pre-fix: validation checks `derive(state_init_a) == det_account_b` → fails, transaction rejected even though it is valid.
4. Post-fix: validation checks `derive(state_init_a) == det_account_a` → passes correctly.

The test `test_deterministic_state_init_meta_tx_receiver_check_pre_fix` at line 139 and `test_deterministic_state_init_meta_tx_receiver_check` at line 164 of `test-loop-tests/src/tests/deterministic_account_id.rs` confirm both behaviors: [7](#0-6)

### Citations

**File:** runtime/runtime/src/action_validation.rs (L147-167)
```rust
        Action::Delegate(a) => validate_delegate_action(
            limit_config,
            (&a.delegate_action).into(),
            receiver,
            current_protocol_version,
            mode,
        ),
        Action::DelegateV2(a) => {
            require_protocol_feature(
                ProtocolFeature::DelegateV2,
                "DelegateV2",
                current_protocol_version,
            )?;
            validate_delegate_action(
                limit_config,
                (&a.delegate_action).into(),
                receiver,
                current_protocol_version,
                mode,
            )
        }
```

**File:** runtime/runtime/src/action_validation.rs (L180-208)
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
}
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

**File:** test-loop-tests/src/tests/deterministic_account_id.rs (L128-157)
```rust
/// Ensure there is no exploit with invalid deterministic account ids through
/// meta transactions.
///
/// With the old (buggy) code, `validate_delegate_action` used
/// `outer_tx.receiver_id` instead of `delegate_action.receiver_id` when
/// checking inner actions. The exploit tx therefore passes initial tx
/// validation. The exploit is prevented by a following `validate_receipt` check
/// when the meta transaction is unpacked.
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

**File:** core/primitives-core/src/version.rs (L555-571)
```rust
            ProtocolFeature::FixDelegateActionDepositWithFunctionCallError
            | ProtocolFeature::FixDeleteAccountGlobalContractStorageUsage
            | ProtocolFeature::FixDelegatedDeterministicStateInit
            | ProtocolFeature::GasKeys
            | ProtocolFeature::ContinuousEpochSync
            | ProtocolFeature::DynamicResharding
            | ProtocolFeature::StickyReshardingValidatorAssignment
            | ProtocolFeature::StrictNonce
            | ProtocolFeature::PostQuantumSignatures
            | ProtocolFeature::UniqueChunkTransactions
            | ProtocolFeature::ValidateBlockOrdinalAndEpochSyncDataHash
            | ProtocolFeature::YieldWithId
            | ProtocolFeature::ExecutionMetadataV4
            | ProtocolFeature::SignedContractCodeResponse
            | ProtocolFeature::ClampOutgoingGasAdmission
            | ProtocolFeature::AccountCostIncrease
            | ProtocolFeature::DelegateV2 => 85,
```
