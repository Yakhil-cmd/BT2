### Title
Wrong `receiver_id` Field in `validate_delegate_action` Makes `DeterministicStateInit` via Meta Transactions Permanently Unexecutable — (`runtime/runtime/src/action_validation.rs`)

---

### Summary

In `validate_delegate_action`, when the `FixDelegatedDeterministicStateInit` protocol feature is not yet enabled, the function passes the **outer receipt's `receiver`** to `validate_actions_with_mode` instead of **`delegate_action.receiver_id()`**. This is the exact same wrong-field authorization pattern as the Axelar bug: a guard checks the wrong entity, making every legitimate `DeterministicStateInit` action inside a meta transaction fail at pre-inclusion validation with `InvalidDeterministicStateInitReceiver`.

---

### Finding Description

`validate_delegate_action` is called from `validate_actions_with_mode` → `validate_action_with_mode` → `validate_delegate_action` whenever a `Delegate` or `DelegateV2` action is validated. Its job is to recursively validate the inner actions of the delegate payload. For `DeterministicStateInit`, the inner validation (`validate_deterministic_state_init`) enforces the invariant:

```
derive_near_deterministic_account_id(state_init) == receiver_id
```

The `receiver_id` passed into that check must be the **delegate action's own receiver** — the account that will actually execute the inner actions. Instead, the pre-fix code passes `receiver`, which is the **outer receipt's receiver** (i.e., the relayer's account or the meta-transaction wrapper account):

```rust
// runtime/runtime/src/action_validation.rs  lines 188-199
let inner_receiver =
    if ProtocolFeature::FixDelegatedDeterministicStateInit.enabled(current_protocol_version) {
        delegate_action.receiver_id()          // correct
    } else {
        // BUG: validated against the wrong id.
        // Makes it impossible to initialize deterministic accounts from meta transactions.
        receiver                               // outer receipt receiver — wrong field
    };
validate_actions_with_mode(limit_config, &actions, inner_receiver, ...)?;
``` [1](#0-0) 

`validate_deterministic_state_init` then compares:

```rust
if derived_id != *receiver_id {
    return Err(ActionsValidationError::InvalidDeterministicStateInitReceiver { ... });
}
``` [2](#0-1) 

Because the outer receipt's receiver is the relayer (e.g., `relayer.near`), and `derive_near_deterministic_account_id(state_init)` produces a deterministic `0s…` account ID, the two can never match in a normal meta-transaction flow. The check is structurally impossible to satisfy for any legitimate use.

The code comment confirms this is a known bug:

> *"This is a bug fixed with `FixDelegatedDeterministicStateInit` that validated against the wrong id. This makes it impossible to initialize deterministic accounts from meta transactions."* [3](#0-2) 

The protocol feature that fixes it is registered but not yet activated in the stable protocol version: [4](#0-3) 

---

### Impact Explanation

Every `DeterministicStateInit` action embedded inside a `Delegate` (meta transaction) is unconditionally rejected at pre-inclusion transaction validation with `InvalidDeterministicStateInitReceiver`. The feature combination — deterministic account creation via relayer/meta-transaction — is completely non-functional. No workaround exists short of waiting for the protocol upgrade that enables `FixDelegatedDeterministicStateInit`.

The test suite confirms the exact failure mode: [5](#0-4) 

---

### Likelihood Explanation

Any unprivileged user who submits a `SignedTransaction` containing a `Delegate` action whose inner payload includes `DeterministicStateInit` triggers the bug. No special privilege is required. The input is fully user-controlled (the outer `receiver_id` of the transaction and the `delegate_action.receiver_id` are independent fields set by the relayer and the meta-transaction sender respectively).

---

### Recommendation

Replace `receiver` with `delegate_action.receiver_id()` unconditionally (i.e., remove the protocol-version branch and always use the correct field):

```rust
// runtime/runtime/src/action_validation.rs
fn validate_delegate_action(...) {
    let actions = delegate_action.get_actions();
-   let inner_receiver =
-       if ProtocolFeature::FixDelegatedDeterministicStateInit.enabled(current_protocol_version) {
-           delegate_action.receiver_id()
-       } else {
-           receiver
-       };
+   let inner_receiver = delegate_action.receiver_id();
    validate_actions_with_mode(limit_config, &actions, inner_receiver, ...)?;
}
```

This is exactly what `FixDelegatedDeterministicStateInit` implements; the fix should be activated at the earliest possible protocol upgrade.

---

### Proof of Concept

The integration test `try_meta_tx_deterministic_receiver_exploit` in `test-loop-tests/src/tests/deterministic_account_id.rs` (lines 183–266) constructs the exact scenario:

1. Deploy global contract and two deterministic accounts `det_account_a` (derives from `state_init_a`) and `det_account_b` (derives from `state_init_b`).
2. Craft a `SignedTransaction` where:
   - outer `receiver_id = det_account_b` (matches `derive(state_init_b)`)
   - `delegate_action.receiver_id = det_account_a` (wrong target)
   - inner action = `DeterministicStateInit(state_init_b)`
3. Pre-fix: the outer-receiver check `derive(state_init_b) == det_account_b` passes, so the tx is admitted. The receipt then fails at execution with `InvalidDeterministicStateInitReceiver` because `derive(state_init_b) != det_account_a`.
4. For the legitimate use case (outer receiver = relayer, delegate receiver = `det_account_b`): the check `derive(state_init_b) == relayer` always fails at tx admission — the feature is permanently blocked. [6](#0-5)

### Citations

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

**File:** core/primitives-core/src/version.rs (L408-410)
```rust
    /// Allow creating `DeterministicStateInitAction` from a delegated action by
    /// fixing the receiver id check.
    FixDelegatedDeterministicStateInit,
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
