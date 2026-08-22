### Title
Pre-fix `validate_delegate_action` used outer transaction's `receiver_id` instead of the `DelegateAction`'s own `receiver_id` when validating a nested `DeterministicStateInitAction`, allowing a delegated deposit/state-init to be misdirected — analogous to the Vader `from`/`to` parameter-mismatch bug - (File: `runtime/runtime/src/action_validation.rs`)

### Summary
The Vader report describes a function that authorizes an operation using one address parameter (`from`, matching an already-granted approval) while the actual recipient/state-affecting target is a second, independently-controlled parameter (`to`), letting an attacker redirect funds by frontrunning with the same `from` but a different `to`. Nearcore has a structurally identical class of bug in delegate-action (meta-transaction) validation: the code that authorizes a nested `DeterministicStateInitAction` checked the *outer* transaction's `receiver_id` (the field trusted/validated by the relayer's transaction) instead of the `DelegateAction`'s own `receiver_id` (the field that actually determines where the inner action executes), i.e., two different "target" fields could diverge and get silently substituted for each other.

### Finding Description
`validate_delegate_action` in `runtime/runtime/src/action_validation.rs` recurses into the inner actions of a `DelegateAction`/`SignedDelegateAction` to validate them (e.g. `DeterministicStateInitAction`, whose validity check compares the derived deterministic account id against the "receiver"). Before the `FixDelegatedDeterministicStateInit` protocol feature, this recursive validation used the wrong receiver identifier: [1](#0-0) 

Specifically, when the feature is disabled, `inner_receiver` is bound to the outer `receiver` parameter (the transaction's top-level `receiver_id`) rather than `delegate_action.receiver_id()` (the field inside the signed `DelegateAction` payload that actually governs where the inner actions, including `DeterministicStateInitAction`, are executed): [2](#0-1) 

This mirrors the Vader class of bug precisely: `validate_deterministic_state_init` (the "mint" analog) checks that the derived account id equals a "target" account, but pre-fix validation supplied the wrong target field (outer tx receiver) instead of the field that will actually be used at execution time (delegate action's own receiver), letting the two diverge: [3](#0-2) 

The divergence is exploitable in a meta-transaction (NEP-366) flow: a relayer submits `Action::Delegate` in a transaction whose outer `receiver_id` equals `det_account_b` (matching the signer's crafted, correctly-derived `state_init_b`), while the signed `DelegateAction.receiver_id` is set to a different account, `det_account_a`. Pre-fix, tx validation used the outer `receiver_id` (`det_account_b`) to check `DeterministicStateInitAction`, which passes, even though the inner action is destined (per the signed `DelegateAction`) for `det_account_a`. This is exactly demonstrated by the test harness added to cover the fix: [4](#0-3) 

The nearcore team added a regression test explicitly documenting the "pre-fix" behavior and the exploit construction: [5](#0-4) 

### Impact Explanation
If reachable, this class of bug would allow a `DeterministicStateInitAction` (which carries an attached `deposit` and sets state/contract code) to pass validation for the wrong receiver id, i.e., validated against `det_account_b` (matching the crafted state) but actually attempting to execute against `det_account_a` at receipt-processing time. This is directly analogous to the Vader issue where validated `from`/authorization does not match where funds actually flow. In the current nearcore codebase, this discrepancy is only reachable at the *transaction admission* stage; the code comment and the "pre-fix" test confirm that a second layer — `validate_receipt` at receipt processing — independently re-derives and re-checks the receiver id, causing the exploit tx to fail there with `InvalidDeterministicStateInitReceiver` even without the fix: [6](#0-5) 

So on the currently-shipped protocol version (the fix is already merged and, per the repo's own assertion, the flaw "cannot be abused" even pre-fix because of the second check), this specific instance does **not** result in actual token theft or unauthorized state changes — it is a validation-order/defense-in-depth gap that has already been closed by `ProtocolFeature::FixDelegatedDeterministicStateInit`, gated and tested via `test_deterministic_state_init_meta_tx_receiver_check_pre_fix` / `test_deterministic_state_init_meta_tx_receiver_check`.

### Likelihood Explanation
Low under the current, shipped protocol version: the second (`validate_receipt`) check independently derives and validates the receiver, per nearcore's own comment and regression tests, so the "pre-fix" behavior is provably non-exploitable in this codebase as it stands. The flaw would only be live on a protocol version that (a) predates `FixDelegatedDeterministicStateInit` **and** (b) lacked the receipt-level re-validation — a combination the current code does not appear to expose.

### Recommendation
No code change is required beyond what is already present: `ProtocolFeature::FixDelegatedDeterministicStateInit` correctly switches `validate_delegate_action` to use `delegate_action.receiver_id()` or `delegate_action.receiver_id()` is already being used. Recommend (a) removing the now-unnecessary two-branch logic once the pre-fix protocol version is fully retired/deprecated in production to reduce complexity and risk of regression, and (b) keeping the receipt-level `validate_receipt` re-check as defense-in-depth for any future action type that similarly needs both tx-time and receipt-time receiver validation, per the same pattern that neutralized this specific issue.

### Proof of Concept
See the existing regression tests, which construct and execute the exact exploit scenario and assert both the pre-fix (would-be-vulnerable) and post-fix (protected) outcomes: [7](#0-6) [4](#0-3) 

**Note on completeness:** I was unable to fully verify from the index alone whether any *other* current, non-deprecated action/host-function path in nearcore has an analogous `from`/`to` (authorized-target vs. actual-target) parameter divergence that is reachable without the receipt-level safety net described above — a full audit of `runtime/runtime/src/action_validation.rs`, `verifier.rs`, and all `promise_batch_action_*` host functions in `runtime/near-vm-runner/src/logic/logic.rs` would be needed to rule this out with certainty across all action types, not just `DeterministicStateInitAction`/`DelegateAction`. Given index size limits, some file contents may not be fully available; a full Devin session with complete repository access would allow that broader audit.

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

**File:** test-loop-tests/src/tests/deterministic_account_id.rs (L177-266)
```rust
/// Set up the exploit scenario and return the result of submitting the exploit tx.
///
/// `det_account_b` is deployed as a deterministic account and given an access key so
/// it can act as meta_tx_sender. The exploit tx wraps `state_init_b` inside a delegate
/// action whose `receiver_id` is `det_account_a` (wrong target). With the fix this is
/// caught at tx validation; without it, tx validation passes but the receipt fails.
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
