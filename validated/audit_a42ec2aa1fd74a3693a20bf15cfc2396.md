### Title
Multisig transaction execution can substitute an unapproved payload when `abort_if_multisig_payload_mismatch` is disabled - (File: `aptos-move/framework/aptos-framework/sources/multisig_account.move`)

### Summary
Reducing the external report to its core invariant: an admission function that is supposed to bind approval/signing material to a specific action can instead accept the wrong material for a different action set. In the Aptos multisig-account flow, `validate_multisig_transaction` is the VM-invoked admission gate that is supposed to ensure the payload being executed is exactly the payload that owners voted/approved for. When the full payload was stored on-chain at proposal time (`transaction.payload = Some(..)`, `payload_hash = None`), the code only checks that the *executed* payload matches the *approved* payload if the feature flag `abort_if_multisig_payload_mismatch_enabled` is turned on. If that flag is off, the equality check is skipped entirely, and any owner with enough approvals can execute an arbitrary different call as the multisig account.

### Finding Description
`validate_multisig_transaction` in [1](#0-0)  performs quorum/timelock checks and then attempts to bind the caller-supplied `payload` to the transaction that was actually approved:

- If only a hash was stored (`payload_hash.is_some()`), it hashes the supplied payload and compares to the stored hash — this path is sound.
- If the full payload was stored (`transaction.payload.is_some()`), the match is only enforced when the feature `features::abort_if_multisig_payload_mismatch_enabled()` is turned on:
```
if (features::abort_if_multisig_payload_mismatch_enabled()
    && transaction.payload.is_some()
    && !payload.is_empty()
) {
    let stored_payload = transaction.payload.borrow();
    assert!(payload == *stored_payload, error::invalid_argument(EPAYLOAD_DOES_NOT_MATCH));
}
``` [2](#0-1) 

If the feature is disabled, this entire branch is skipped, so a `payload` mismatching the stored, owner-approved payload is not rejected here.

The VM-side caller, `execute_multisig_transaction` in `aptos_vm.rs`, then retrieves the payload to actually execute via `GET_NEXT_TRANSACTION_PAYLOAD` using the same caller-supplied `provided_payload` bytes [3](#0-2) , and finally deserializes and executes that payload as the multisig account via `execute_multisig_payload` [4](#0-3) . Both the VM-side gate at `run_multisig_prologue` [5](#0-4)  and the framework-side `validate_multisig_transaction` share the same feature-gated skip, so mempool/VM admission and execution agree — but they agree on the *wrong* thing when the flag is off: they both accept an unmatched payload.

This is exactly the admission-binding failure class from the external report generalized to Aptos: the approval set (owner votes/quorum) is meant to authorize one specific action, but the admission check that should bind "approved payload" to "executed payload" can be bypassed by a feature-flag state, letting an executor substitute a different call while still consuming the quorum built for the original proposal.

### Impact Explanation
If reachable (flag disabled), any single owner who can gather quorum approvals for *some* transaction, or who can front-run/observe the timing after quorum is reached, could execute a completely different entry function/script under the multisig account's signer authority — including moving funds or changing multisig configuration — even though the other owners approved a different, benign payload. This is unauthorized execution under the wrong "approval set" binding, matching the required "Authenticator/multisig/approval validation accepting the wrong approval set" impact class.

### Likelihood Explanation
Likelihood is directly gated by the state of the `abort_if_multisig_payload_mismatch` feature flag at runtime. I could not verify in this pass whether this flag is currently enabled by default / already activated via governance on the network this repo snapshot represents — grep for the flag only surfaced its definition and usage sites (`features.move`, `multisig_account.move`, `aptos_vm.rs`, `transaction_validation.rs`) but not an explicit "enabled by default in genesis/mainnet" configuration in the portion of the codebase indexed. If the flag is already permanently enabled on production networks, this is not exploitable there and the finding is only a defense-in-depth / legacy-network concern. This uncertainty should be resolved by checking the current on-chain feature-flag state (via governance proposal history or `aptos_framework::features` default initialization) before treating this as an actively exploitable mainnet bug.

### Recommendation
Make the payload-match assertion for the full-payload-stored case unconditional (remove the feature-flag gate), or at minimum flip the default so any owner-created transaction with an on-chain-stored payload always requires an exact match at execution regardless of feature-flag rollout state. If backward compatibility motivated the flag, ensure it is enabled and can no longer be disabled once quorum-authorization semantics depend on it.

### Proof of Concept
1. Ensure `abort_if_multisig_payload_mismatch_enabled` feature is OFF.
2. Owner A calls `create_transaction(owner, multisig_account, payload_transfer_to_charity)` — full payload stored on-chain, `payload_hash = None`.
3. Owners B, C approve via `approve_transaction`, reaching quorum for that specific payload.
4. Owner A (or any owner with the "final" approval) submits a `MultisigTransaction` at the VM layer with `TransactionExecutableRef::EntryFunction` pointing to a *different* entry function (e.g., drain funds to attacker), i.e. `provided_payload != stored_payload`.
5. `run_multisig_prologue` → `validate_multisig_transaction` only checks quorum count and timelock; because `transaction.payload_hash` is `None` and the feature flag is off, the payload-equality assertion block is skipped.
6. `execute_multisig_transaction` executes the attacker-chosen payload under the multisig account's signer authority, consuming the quorum that was built for the original, different, approved payload. [2](#0-1) [6](#0-5) [7](#0-6)

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1328-1385)
```text
    fun validate_multisig_transaction(
        owner: &signer, multisig_account: address, payload: vector<u8>) {
        assert_multisig_account_exists(multisig_account);
        assert_is_owner(owner, multisig_account);
        let sequence_number = last_resolved_sequence_number(multisig_account) + 1;
        assert_transaction_exists(multisig_account, sequence_number);

        if (features::multisig_v2_enhancement_feature_enabled()) {
            assert!(
                can_execute(address_of(owner), multisig_account, sequence_number),
                error::invalid_argument(ENOT_ENOUGH_APPROVALS),
            );
        }
        else {
            assert!(
                can_be_executed(multisig_account, sequence_number),
                error::invalid_argument(ENOT_ENOUGH_APPROVALS),
            );
        };

        // Count approvals, including the executing owner's implicit vote.
        let (num_approvals, _) = num_approvals_and_rejections(multisig_account, sequence_number);
        if (!has_voted_for_approval(multisig_account, sequence_number, address_of(owner))) {
            num_approvals += 1;
        };
        assert!(num_approvals >= num_signatures_required(multisig_account), error::invalid_argument(ENOT_ENOUGH_APPROVALS));

        // Timelock check — separate from quorum so the error is unambiguous.
        assert!(
            can_execute_with_timelock(multisig_account, sequence_number, num_approvals),
            error::invalid_state(ETIMELOCK_NOT_EXPIRED),
        );

        // If the transaction payload is not stored on chain, verify that the provided payload matches the hashes stored
        // on chain.
        let multisig_account_resource = borrow_global<MultisigAccount>(multisig_account);
        let transaction = multisig_account_resource.transactions.borrow(sequence_number);
        if (transaction.payload_hash.is_some()) {
            let payload_hash = transaction.payload_hash.borrow();
            assert!(
                sha3_256(payload) == *payload_hash,
                error::invalid_argument(EPAYLOAD_DOES_NOT_MATCH_HASH),
            );
        };

        // If the transaction payload is stored on chain and there is a provided payload,
        // verify that the provided payload matches the stored payload.
        if (features::abort_if_multisig_payload_mismatch_enabled()
            && transaction.payload.is_some()
            && !payload.is_empty()
        ) {
            let stored_payload = transaction.payload.borrow();
            assert!(
                payload == *stored_payload,
                error::invalid_argument(EPAYLOAD_DOES_NOT_MATCH),
            );
        }
    }
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1305-1347)
```rust
        let provided_payload = match executable {
            TransactionExecutableRef::EntryFunction(entry_func) => {
                // TODO[Orderless]: For backward compatibility reasons, still using `MultisigTransactionPayload` here.
                // Find a way to deprecate this.
                bcs::to_bytes(&MultisigTransactionPayload::EntryFunction(
                    entry_func.clone(),
                ))
                .map_err(|_| invariant_violation_error())?
            },
            TransactionExecutableRef::Empty => {
                // Default to empty bytes if payload is not provided.
                if self
                    .features()
                    .is_abort_if_multisig_payload_mismatch_enabled()
                {
                    vec![]
                } else {
                    bcs::to_bytes::<Vec<u8>>(&vec![]).map_err(|_| invariant_violation_error())?
                }
            },
            TransactionExecutableRef::Script(script) => {
                if !self.features().is_multisig_script_enabled() {
                    let s = VMStatus::error(
                        StatusCode::FEATURE_UNDER_GATING,
                        Some("Multisig script payload is not enabled".to_string()),
                    );
                    return Ok((s, discarded_output(StatusCode::FEATURE_UNDER_GATING)));
                }
                bcs::to_bytes(&MultisigTransactionPayload::Script(script.clone()))
                    .map_err(|_| invariant_violation_error())?
            },
            TransactionExecutableRef::Encrypted => {
                // Decryption failed. Return an error so the caller runs the failure epilogue,
                // which increments the sequence number and charges gas.
                return Err(VMStatus::error(
                    StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT,
                    Some(
                        "Encrypted multisig transaction decryption failed; payload not available"
                            .to_string(),
                    ),
                ));
            },
        };
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1349-1367)
```rust
        let payload_bytes: Vec<Vec<u8>> = session
            .execute(|session| {
                session.execute_function_bypass_visibility(
                    &MULTISIG_ACCOUNT_MODULE,
                    GET_NEXT_TRANSACTION_PAYLOAD,
                    vec![],
                    serialize_values(&vec![
                        MoveValue::Address(multisig_address),
                        MoveValue::vector_u8(provided_payload),
                    ]),
                    gas_meter,
                    traversal_context,
                    code_storage,
                )
            })?
            .return_values
            .into_iter()
            .map(|(bytes, _ty)| bytes)
            .collect::<Vec<_>>();
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1468-1505)
```rust
    fn execute_multisig_payload(
        &self,
        resolver: &impl AptosMoveResolver,
        code_storage: &impl AptosCodeStorage,
        mut session: UserSession,
        gas_meter: &mut impl AptosGasMeter,
        traversal_context: &mut TraversalContext,
        multisig_address: AccountAddress,
        payload: &MultisigTransactionPayload,
        change_set_configs: &ChangeSetConfigs,
        trace_recorder: &mut impl TraceRecorder,
    ) -> Result<UserSessionChangeSet, VMStatus> {
        let serialized_signers =
            SerializedSigners::new(vec![serialized_signer(&multisig_address)], None);

        // If txn args are not valid, we'd still consider the transaction as executed but
        // failed. This is primarily because it's unrecoverable at this point.
        session.execute(|session| match payload {
            MultisigTransactionPayload::EntryFunction(entry_function) => self
                .validate_and_execute_entry_function(
                    code_storage,
                    session,
                    &serialized_signers,
                    gas_meter,
                    traversal_context,
                    entry_function,
                    trace_recorder,
                ),
            MultisigTransactionPayload::Script(script) => self.validate_and_execute_script(
                session,
                &serialized_signers,
                code_storage,
                gas_meter,
                traversal_context,
                script,
                trace_recorder,
            ),
        })?;
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L419-479)
```rust
pub(crate) fn run_multisig_prologue(
    session: &mut SessionExt<impl AptosMoveResolver>,
    module_storage: &impl ModuleStorage,
    txn_data: &TransactionMetadata,
    executable: TransactionExecutableRef,
    multisig_address: AccountAddress,
    features: &Features,
    log_context: &AdapterLogSchema,
    traversal_context: &mut TraversalContext,
) -> Result<(), VMStatus> {
    let unreachable_error = VMStatus::error(StatusCode::UNREACHABLE, None);
    // Note[Orderless]: Earlier the `provided_payload` was being calculated as bcs::to_bytes(MultisigTransactionPayload::EntryFunction(entry_function)).
    // So, converting the executable to this format.
    let provided_payload = match executable {
        TransactionExecutableRef::EntryFunction(entry_function) => bcs::to_bytes(
            &MultisigTransactionPayload::EntryFunction(entry_function.clone()),
        )
        .map_err(|_| unreachable_error.clone())?,
        TransactionExecutableRef::Empty => {
            if features.is_abort_if_multisig_payload_mismatch_enabled() {
                vec![]
            } else {
                bcs::to_bytes::<Vec<u8>>(&vec![]).map_err(|_| unreachable_error.clone())?
            }
        },
        TransactionExecutableRef::Script(script) => {
            if !features.is_multisig_script_enabled() {
                return Err(VMStatus::error(
                    StatusCode::FEATURE_UNDER_GATING,
                    Some("Multisig script payload is not enabled".to_string()),
                ));
            }
            bcs::to_bytes(&MultisigTransactionPayload::Script(script.clone()))
                .map_err(|_| unreachable_error.clone())?
        },
        TransactionExecutableRef::Encrypted => {
            return Err(VMStatus::error(
                StatusCode::FEATURE_UNDER_GATING,
                Some("Encrypted payload not supported for multisig transactions".to_string()),
            ));
        },
    };

    session
        .execute_function_bypass_visibility(
            &MULTISIG_ACCOUNT_MODULE,
            VALIDATE_MULTISIG_TRANSACTION,
            vec![],
            serialize_values(&vec![
                MoveValue::Signer(txn_data.sender),
                MoveValue::Address(multisig_address),
                MoveValue::vector_u8(provided_payload),
            ]),
            &mut UnmeteredGasMeter,
            traversal_context,
            module_storage,
        )
        .map(|_return_vals| ())
        .map_err(expect_no_verification_errors)
        .or_else(|err| convert_prologue_error(err, log_context))
}
```
