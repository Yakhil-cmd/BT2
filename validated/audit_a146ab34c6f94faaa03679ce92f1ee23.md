## Finding: Multisig payload substitution bypasses owner-approved transaction content when `abort_if_multisig_payload_mismatch` is disabled

### Title
Multisig transaction execution can substitute an unapproved payload for the stored, voted-on payload — ([File: aptos-move/framework/aptos-framework/sources/multisig_account.move])

### Summary
`multisig_account::validate_multisig_transaction`, the Move function invoked by the VM prologue as the sole admission check for multisig transaction execution, only verifies that the *executed* payload matches the *stored/approved* payload when the feature `abort_if_multisig_payload_mismatch_enabled` is turned on. When that feature is off, an executing owner can submit a completely different payload than the one that other owners voted to approve, and it will still execute — reusing votes cast for a different, on-chain-stored transaction.

### Finding Description
For a multisig transaction created with `create_transaction` (full payload stored on-chain, as opposed to `create_transaction_with_hash`), the admission logic in `validate_multisig_transaction` is: [1](#0-0) 

- If only a **hash** was stored (`transaction.payload_hash.is_some()`), the executed `payload` is unconditionally checked against that hash (lines 1365–1371) — this path is safe.
- If the **full payload** was stored (`transaction.payload.is_some()`), the check that the executed `payload` equals the `stored_payload` is gated behind `features::abort_if_multisig_payload_mismatch_enabled()` (lines 1375–1384). If this feature is disabled, **no comparison happens at all**.

The VM prologue (`run_multisig_prologue`) computes `provided_payload` directly from the `executable` field of the *submitted* `SignedTransaction` (attacker/owner controlled at submission time), not from the stored transaction: [2](#0-1) 

This `provided_payload` is passed into `validate_multisig_transaction`, and the same value is later used by `execute_multisig_transaction` to actually resolve the executed payload via `GET_NEXT_TRANSACTION_PAYLOAD`: [3](#0-2) [4](#0-3) 

Because the mismatch enforcement is a single, disable-able feature flag guarding the *only* place that binds "what owners approved" to "what actually executes," a multisig owner who has voting rights (and therefore is permitted to call `execute`) can:
1. Have a legitimate proposal (e.g., a harmless entry function call) created via `create_transaction` and approved by the required number of owners.
2. When it becomes their turn to execute (`sequence_number == last_resolved_sequence_number + 1`), submit a `MultisigTransaction` execution with a **different** `executable`/payload than what was stored and voted on.
3. `validate_multisig_transaction` passes because vote/threshold checks (lines 1335–1359) only examine vote counts for the sequence number, not payload identity, and the payload-equality assertion is skipped when the feature is off.
4. `execute_multisig_transaction` resolves and executes the substituted payload as the multisig account.

This is a pre-validation/admission mismatch: the accepted transaction executes and commits an action under a different approval set/content than what the quorum actually authorized, i.e., the authenticated action (owner's execute call) does not bind to the content that received the required approvals.

### Impact Explanation
This breaks the core security guarantee of the enhanced multisig module — that execution requires k-of-n approval **of the specific transaction content**. An executing owner (who need not individually hold k-of-n authority) can unilaterally redirect approved capital/authority (the multisig account, which typically holds funds or admin capabilities) toward an arbitrary entry function or script of their choosing, as long as they are one of the owners entitled to execute a pending, sufficiently-voted sequence slot. This is a high-severity authorization/approval-binding failure at the transaction admission boundary specifically named in the task's impact list ("Authenticator, WebAuthn, multisig, or approval validation accepting the wrong signing material or wrong approval set").

### Likelihood Explanation
The likelihood is entirely conditional on the on-chain state of the `abort_if_multisig_payload_mismatch_enabled` feature flag. I was not able to verify from the fetched code snippets whether this feature is enabled by default on mainnet/testnet or remains an opt-in/rollout flag (the flag is referenced in `aptos-move/framework/move-stdlib/sources/configs/features.move`, `types/src/on_chain_config/aptos_features.rs`, but I did not confirm its default/enabled status in the current genesis or feature-flags rollout config). If it is disabled on any live network (or can be toggled off/is off during a migration window), the bypass is directly exploitable by any owner with execute rights on a full-payload multisig proposal. This uncertainty should be resolved before treating this as confirmed-exploitable on a specific deployed network.

### Recommendation
- Make the payload-match assertion (lines 1375–1384) unconditional (remove the feature gate), so that whenever a full payload is stored on-chain, the payload actually executed must match it, regardless of feature flag state.
- Audit call sites and, if the feature must remain toggleable for migration reasons, ensure the flag defaults to enabled and cannot be disabled once enabled (a one-way feature, similar to other security-hardening feature flags in the codebase).

### Proof of Concept
1. Owner A calls `multisig_account::create_transaction(owner_a, multisig_addr, PAYLOAD_BENIGN)` — this stores `PAYLOAD_BENIGN` on-chain and implicitly votes for it.
2. Owners B and C call `approve_transaction(owner_b/c, multisig_addr, seq)` until `num_signatures_required` is met for `seq`.
3. On a network/state where `features::abort_if_multisig_payload_mismatch_enabled()` returns `false`, Owner A (or any owner allowed to execute per `can_execute`) submits a `TransactionPayload::Multisig { multisig_address: multisig_addr, transaction_payload: Some(PAYLOAD_MALICIOUS) }` transaction instead of `None`/`PAYLOAD_BENIGN`.
4. `run_multisig_prologue` computes `provided_payload = bcs::to_bytes(MultisigTransactionPayload::EntryFunction(PAYLOAD_MALICIOUS))` and calls `validate_multisig_transaction`; since `transaction.payload_hash` is `none` (full payload was stored, not a hash) and the mismatch-check feature is disabled, no assertion fires.
5. `execute_multisig_transaction` resolves the payload via `GET_NEXT_TRANSACTION_PAYLOAD` using the malicious `provided_payload` and executes `PAYLOAD_MALICIOUS` as the multisig account — despite owners B and C never having approved it.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1361-1385)
```text
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

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L419-460)
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
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1299-1347)
```rust
        // Step 1: Obtain the payload. If any errors happen here, the entire transaction should fail
        let invariant_violation_error = || {
            PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                .with_message("MultiSig transaction error".to_string())
                .finish(Location::Undefined)
        };
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1349-1389)
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
        let payload_bytes = payload_bytes
            .first()
            // We expect the payload to either exists on chain or be passed along with the
            // transaction.
            .ok_or_else(|| {
                PartialVMError::new(StatusCode::UNKNOWN_INVARIANT_VIOLATION_ERROR)
                    .with_message("Multisig payload bytes return error".to_string())
                    .finish(Location::Undefined)
            })?;
        // We have to deserialize twice as the first time returns the actual return type of the
        // function, which is vec<u8>. The second time deserializes it into the correct
        // EntryFunction payload type.
        // If either deserialization fails for some reason, that means the user provided incorrect
        // payload data either during transaction creation or execution.
        let deserialization_error = || {
            PartialVMError::new(StatusCode::FAILED_TO_DESERIALIZE_ARGUMENT)
                .finish(Location::Undefined)
        };
        let payload_bytes =
            bcs::from_bytes::<Vec<u8>>(payload_bytes).map_err(|_| deserialization_error())?;
        let payload = bcs::from_bytes::<MultisigTransactionPayload>(&payload_bytes)
            .map_err(|_| deserialization_error())?;
```
