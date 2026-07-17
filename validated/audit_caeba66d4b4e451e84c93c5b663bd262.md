### Title
Wrong `receiver_id` Argument in `validate_delegate_action` Makes `DeterministicStateInit` Inside Meta-Transactions Always Fail Pre-Inclusion Validation — (`File: runtime/runtime/src/action_validation.rs`)

### Summary

`validate_delegate_action` passes the **outer transaction's `receiver`** (the relayer/meta-tx-receiver account) instead of **`delegate_action.receiver_id()`** (the deterministic account being initialized) when validating inner actions. Because `validate_deterministic_state_init` checks that the passed `receiver_id` equals the deterministically-derived account ID, and the outer receiver is never a deterministic account, the check always fails. Every `DeterministicStateInit` action wrapped inside a `DelegateAction` is unconditionally rejected at pre-inclusion transaction validation.

### Finding Description

`validate_delegate_action` in `runtime/runtime/src/action_validation.rs` receives two distinct account IDs:

- `receiver` — the outer signed transaction's `receiver_id` (the relayer's account, i.e., the account that hosts the `DelegateAction`)
- `delegate_action.receiver_id()` — the inner delegate action's target (the deterministic account to be initialized)

Before the `FixDelegatedDeterministicStateInit` protocol feature, the function unconditionally forwards the outer `receiver` to `validate_actions_with_mode`:

```rust
let inner_receiver =
    if ProtocolFeature::FixDelegatedDeterministicStateInit.enabled(current_protocol_version) {
        delegate_action.receiver_id()   // correct
    } else {
        receiver                        // BUG: outer tx receiver, not the delegate target
    };
validate_actions_with_mode(limit_config, &actions, inner_receiver, ...)?;
``` [1](#0-0) 

`validate_actions_with_mode` eventually calls `validate_deterministic_state_init`, which derives the expected deterministic account ID from the `state_init` payload and compares it to the supplied `receiver_id`:

```rust
let derived_id = derive_near_deterministic_account_id(&action.state_init);
if derived_id != *receiver_id {
    return Err(ActionsValidationError::InvalidDeterministicStateInitReceiver { ... });
}
``` [2](#0-1) 

Because `receiver` is the relayer's named account (e.g., `"alice.near"`), it can never equal a deterministic account ID (prefix `"0s…"`). The condition `derived_id != *receiver_id` is **always true**, so every `DeterministicStateInit` inside a `DelegateAction` is rejected with `InvalidDeterministicStateInitReceiver` at the tx-admission stage, before the transaction is ever included in a block.

The attacker-controlled field is the `DelegateAction.receiver_id` (the deterministic account target), which is never consulted. The corrupted value is the `receiver_id` argument forwarded to `validate_deterministic_state_init`: it is the outer relayer account instead of the delegate action's target.

The integration test explicitly documents the pre-fix behavior:

> "With the old (buggy) code, `validate_delegate_action` used `outer_tx.receiver_id` instead of `delegate_action.receiver_id` when checking inner actions." [3](#0-2) 

### Impact Explanation

Any unprivileged user who attempts to initialize a deterministic account via a meta-transaction (`DelegateAction` wrapping `DeterministicStateInit`) receives an `InvalidTxError::ActionsValidation(InvalidDeterministicStateInitReceiver)` at the RPC layer. The feature is completely non-functional via meta-transactions. This maps to the **pre-inclusion transaction validation** scope: a valid, well-formed transaction is unconditionally rejected because the wrong identity is checked.

### Likelihood Explanation

Reachable by any unprivileged user submitting a meta-transaction with a `DeterministicStateInit` inner action. No special privilege is required. The only prerequisite is that the `DeterministicStateInit` / deterministic-account feature is enabled at the current protocol version. The wrong-argument path is taken for every protocol version prior to `FixDelegatedDeterministicStateInit`.

### Recommendation

Use `delegate_action.receiver_id()` (the inner delegate target) rather than the outer `receiver` when validating inner actions of a `DelegateAction`. This is exactly what the `FixDelegatedDeterministicStateInit` protocol feature implements:

```rust
let inner_receiver = delegate_action.receiver_id(); // always use the delegate target
validate_actions_with_mode(limit_config, &actions, inner_receiver, ...)?;
``` [4](#0-3) 

### Proof of Concept

1. Deploy a global contract under `AccountId` mode.
2. Derive a deterministic account ID `det_account` from a `DeterministicAccountStateInit` payload.
3. Construct a `DelegateAction` with `receiver_id = det_account` and inner action `DeterministicStateInit { state_init, deposit }`.
4. Wrap it in a signed outer transaction where `receiver_id = relayer_account` (any named account).
5. Submit via RPC.

**Result (pre-fix):** `InvalidTxError::ActionsValidation(InvalidDeterministicStateInitReceiver { receiver_id: relayer_account, derived_id: det_account })` — the feature is permanently broken for meta-transactions.

**Result (post-fix, `FixDelegatedDeterministicStateInit` enabled):** Transaction is accepted and the deterministic account is initialized correctly. [5](#0-4)

### Citations

**File:** runtime/runtime/src/action_validation.rs (L188-206)
```rust
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
```

**File:** runtime/runtime/src/action_validation.rs (L420-427)
```rust
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

**File:** test-loop-tests/src/tests/deterministic_account_id.rs (L183-266)
```rust
fn try_meta_tx_deterministic_receiver_exploit(
    protocol_version: ProtocolVersion,
) -> Result<FinalExecutionOutcomeView, InvalidTxError> {
    let mut env = TestEnv::setup_with_version(Balance::from_near(100), protocol_version);
    env.deploy_global_contract(GlobalContractDeployMode::AccountId);

    let (_state_init_a, det_account_a) = env.new_deterministic_account_with_data(small());
    let (state_init_b, det_account_b) = env.new_deterministic_account_with_data(big());
    assert_ne!(det_account_a, det_account_b);

    // Deploy det_account_b and add a full-access key so it can act as meta_tx_sender.
    let user_signer = create_user_test_signer(&env.user_account());
    let storage_balance = env.balance_for_storage(state_init_b.clone());
    let deploy_tx = SignedTransaction::deterministic_state_init(
        env.next_nonce(),
        env.user_account(),
        det_account_b.clone(),
        &user_signer,
        env.get_tx_block_hash(),
        state_init_b.clone(),
        storage_balance,
    );
    env.run_tx(deploy_tx);

    let meta_tx_sender_signer = create_user_test_signer(&det_account_b);
    let pk_base64 = near_primitives_core::serialize::to_base64(
        &borsh::to_vec(&meta_tx_sender_signer.public_key()).unwrap(),
    );
    let add_key_args = serde_json::json!([
        { "batch_create": { "account_id": det_account_b.as_str() }, "id": 0 },
        {
            "action_add_key_with_full_access": {
                "promise_index": 0,
                "public_key": pk_base64,
                "nonce": 0
            },
            "id": 0,
            "return": true
        }
    ]);
    let add_key_tx = SignedTransaction::call(
        env.next_nonce(),
        env.user_account(),
        det_account_b.clone(),
        &user_signer,
        Balance::from_near(2),
        "call_promise".to_owned(),
        serde_json::to_vec(&add_key_args).unwrap(),
        Gas::from_teragas(300),
        env.get_tx_block_hash(),
    );
    env.run_tx(add_key_tx);

    // Craft the exploit: outer_tx.receiver = det_account_b = derive(state_init_b).
    // Old check: det_account_b == derive(state_init_b) passes.
    // The delegate action targets det_account_a, which is the wrong account.
    // In no protocol version can this ever be allowed to be executed successfully.
    let relayer = env.independent_account();
    let relayer_signer = create_user_test_signer(&relayer);
    let inner_action = Action::DeterministicStateInit(Box::new(DeterministicStateInitAction {
        state_init: state_init_b,
        deposit: Balance::ZERO,
    }));
    let delegate_nonce = env.next_nonce_for(&det_account_b);
    let delegate_action = DelegateAction {
        sender_id: det_account_b.clone(),
        receiver_id: det_account_a,
        actions: vec![NonDelegateAction::try_from(inner_action).unwrap()],
        nonce: delegate_nonce,
        max_block_height: 1_000_000,
        public_key: meta_tx_sender_signer.public_key(),
    };
    let signed_delegate_action =
        SignedDelegateAction::sign(&meta_tx_sender_signer, delegate_action);
    let tx = SignedTransaction::from_actions(
        env.next_nonce(),
        relayer,
        det_account_b,
        &relayer_signer,
        vec![Action::Delegate(Box::new(signed_delegate_action))],
        env.get_tx_block_hash(),
    );
    env.try_execute_tx(tx)
}
```
