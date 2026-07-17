### Title
Missing Early Return in `validate_delegate_action_key` Allows Subsequent Check to Overwrite `DepositWithFunctionCall` Authorization Error — (`runtime/runtime/src/actions.rs`)

### Summary

In `validate_delegate_action_key`, when a `DelegateAction` is signed with a `FunctionCallPermission` access key and the inner function call carries a non-zero deposit, the code sets `result.result = Err(DepositWithFunctionCall)` but **does not return early**. Execution falls through to the `receiver_id` and `method_name` checks. If either of those checks also fails, it overwrites `result.result` with a different error (`ReceiverMismatch` or `MethodNameMismatch`). If both pass, execution reaches the nonce-update block at line 685 and commits the nonce increment to the `TrieUpdate` even though the action is supposed to be rejected.

### Finding Description

In `runtime/runtime/src/actions.rs`, `validate_delegate_action_key` validates the access key used to sign a `DelegateAction`. When the access key has `FunctionCallPermission`, the function checks three constraints in sequence: (1) the inner action must be a single `FunctionCall`, (2) the deposit must be zero, (3) the receiver and method name must match the permission. The deposit check at line 637 sets the error but, before protocol version 85, does not return:

```rust
if function_call.deposit > Balance::ZERO {
    result.result = Err(ActionErrorKind::DelegateActionAccessKeyError(
        InvalidAccessKeyError::DepositWithFunctionCall,
    ).into());
    // Before this fix, the missing early return allowed execution
    // to fall through to the receiver_id and method_name checks,
    // which could overwrite this error with a different one.
    if ProtocolFeature::FixDelegateActionDepositWithFunctionCallError
        .enabled(apply_state.current_protocol_version)
    {
        return Ok(());
    }
}
``` [1](#0-0) 

Execution then reaches the `receiver_id` check at line 651. If the receiver does not match, `ReceiverMismatch` overwrites `DepositWithFunctionCall` in `result.result`. If the receiver and method name both match, execution falls all the way through to the nonce-update block:

```rust
match nonce_update {
    DelegateNonceUpdate::AccessKey => {
        access_key.nonce = delegate_nonce.nonce();
        set_access_key(state_update, sender_id.clone(), public_key.clone(), &access_key);
    }
    ...
}
``` [2](#0-1) 

This is the exact same structural defect as M-18: an intermediate error is set but the function continues processing, allowing later logic to corrupt the result.

The bug is confirmed by the protocol feature description:

> "Fix missing early return on DepositWithFunctionCall error path in validate_delegate_action_key. Previously the error could be overwritten by a subsequent receiver_id or method_name check." [3](#0-2) 

And by the regression test that explicitly asserts the pre-fix behavior:

```rust
// Legacy: missing early return lets ReceiverMismatch overwrite DepositWithFunctionCall.
assert_eq!(result.result, Err(ActionErrorKind::DelegateActionAccessKeyError(
    InvalidAccessKeyError::ReceiverMismatch { ... }
).into()));
``` [4](#0-3) 

The fix is gated behind `ProtocolFeature::FixDelegateActionDepositWithFunctionCallError`, assigned to protocol version 85: [5](#0-4) 

### Impact Explanation

**Authorization invariant broken**: A `DelegateAction` signed with a `FunctionCallPermission` key that carries `deposit > 0` must be rejected with `DepositWithFunctionCall`. Before the fix, if the receiver also mismatches, the reported error is `ReceiverMismatch` — the wrong authorization error. Relayers and on-chain error handlers that branch on the specific error kind receive incorrect information about why the meta-transaction was rejected.

**Nonce committed on rejected action**: In the scenario where `deposit > 0` but the receiver and method name both match the permission, execution reaches `set_access_key` at line 688 and writes the incremented nonce to the `TrieUpdate` before `result.result` is checked by the caller. Depending on whether the caller rolls back the `TrieUpdate` on a non-`Ok` `result.result`, the sender's access key nonce may be permanently advanced even though the action was rejected. This would prevent the sender from reusing that nonce slot for a legitimate future `DelegateAction`. [2](#0-1) 

### Likelihood Explanation

Any unprivileged user can craft a `DelegateAction` signed with a `FunctionCallPermission` key and attach a non-zero deposit. This is a normal user-controlled input path (meta-transaction submission via a relayer). No validator or operator privilege is required. The bug is reachable on any node running protocol version < 85.

### Recommendation

The fix is already present in the codebase behind `ProtocolFeature::FixDelegateActionDepositWithFunctionCallError` (protocol version 85). The unconditional `return Ok(())` after setting `DepositWithFunctionCall` must be applied regardless of protocol version, or the legacy branch must be removed once version 85 is universally deployed. The legacy fall-through path should not remain in production code.

### Proof of Concept

1. Create an account `sender` with a `FunctionCallPermission` access key allowing calls to `receiver.near`, any method, no allowance.
2. Craft a `DelegateAction` with `receiver_id = "other.near"` (mismatches permission) and a single `FunctionCall` action with `deposit = 1 yoctoNEAR`.
3. Submit via a relayer on a node running protocol version < 85.
4. Observe: the returned error is `ReceiverMismatch` instead of `DepositWithFunctionCall`.
5. Craft a second `DelegateAction` with `receiver_id = "receiver.near"` (matches permission) and `deposit = 1 yoctoNEAR`.
6. Submit via a relayer on protocol version < 85.
7. Observe: `result.result` is `DepositWithFunctionCall` (correct error), but `set_access_key` has already been called with the incremented nonce — the nonce may be committed to state even though the action failed. [6](#0-5)

### Citations

**File:** runtime/runtime/src/actions.rs (L636-683)
```rust
        if let Some(Action::FunctionCall(function_call)) = actions.get(0) {
            if function_call.deposit > Balance::ZERO {
                result.result = Err(ActionErrorKind::DelegateActionAccessKeyError(
                    InvalidAccessKeyError::DepositWithFunctionCall,
                )
                .into());
                // Before this fix, the missing early return allowed execution
                // to fall through to the receiver_id and method_name checks,
                // which could overwrite this error with a different one.
                if ProtocolFeature::FixDelegateActionDepositWithFunctionCallError
                    .enabled(apply_state.current_protocol_version)
                {
                    return Ok(());
                }
            }
            if delegate_action.receiver_id() != &function_call_permission.receiver_id {
                result.result = Err(ActionErrorKind::DelegateActionAccessKeyError(
                    InvalidAccessKeyError::ReceiverMismatch {
                        tx_receiver: delegate_action.receiver_id().clone(),
                        ak_receiver: function_call_permission.receiver_id.clone(),
                    },
                )
                .into());
                return Ok(());
            }
            if !function_call_permission.method_names.is_empty()
                && function_call_permission
                    .method_names
                    .iter()
                    .all(|method_name| &function_call.method_name != method_name)
            {
                result.result = Err(ActionErrorKind::DelegateActionAccessKeyError(
                    InvalidAccessKeyError::MethodNameMismatch {
                        method_name: function_call.method_name.clone(),
                    },
                )
                .into());
                return Ok(());
            }
        } else {
            // There should Action::FunctionCall when "function call" permission is used
            result.result = Err(ActionErrorKind::DelegateActionAccessKeyError(
                InvalidAccessKeyError::RequiresFullAccess,
            )
            .into());
            return Ok(());
        }
    };
```

**File:** runtime/runtime/src/actions.rs (L685-699)
```rust
    match nonce_update {
        DelegateNonceUpdate::AccessKey => {
            access_key.nonce = delegate_nonce.nonce();
            set_access_key(state_update, sender_id.clone(), public_key.clone(), &access_key);
        }
        DelegateNonceUpdate::GasKey { nonce_index } => {
            set_gas_key_nonce(
                state_update,
                sender_id.clone(),
                public_key.clone(),
                nonce_index,
                delegate_nonce.nonce(),
            );
        }
    }
```

**File:** runtime/runtime/src/actions.rs (L1763-1781)
```rust
    #[test]
    fn test_delegate_deposit_with_function_call_reports_receiver_mismatch_before_fix() {
        let version =
            ProtocolFeature::FixDelegateActionDepositWithFunctionCallError.protocol_version() - 1;
        let result = deposit_with_function_call_and_receiver_mismatch(version);

        // Legacy: missing early return lets ReceiverMismatch overwrite
        // DepositWithFunctionCall.
        assert_eq!(
            result.result,
            Err(ActionErrorKind::DelegateActionAccessKeyError(
                InvalidAccessKeyError::ReceiverMismatch {
                    tx_receiver: "token.test.near".parse().unwrap(),
                    ak_receiver: "other.test.near".parse().unwrap(),
                },
            )
            .into()),
        );
    }
```

**File:** core/primitives-core/src/version.rs (L349-352)
```rust
    /// Fix missing early return on DepositWithFunctionCall error path in
    /// validate_delegate_action_key. Previously the error could be
    /// overwritten by a subsequent receiver_id or method_name check.
    FixDelegateActionDepositWithFunctionCallError,
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
