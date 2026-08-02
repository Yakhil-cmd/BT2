## Local Admission-Analog Candidate

### Title
Multisig transaction execution can bypass approved-payload binding when full payload is stored on-chain and `abort_if_multisig_payload_mismatch` is disabled - (File: aptos-move/framework/aptos-framework/sources/multisig_account.move)

### Summary
The external report's core invariant is: *a code path meant to reconcile/verify pending state before allowing a new action to proceed can be conditionally skipped, letting stale/mismatched state be used instead of being validated*. The closest Aptos-native analog is in `multisig_account::validate_multisig_transaction`, the VM prologue gate that determines whether the `payload` an executor supplies at execution time is the one that owners actually approved.

### Finding Description
When an owner creates a multisig transaction with `create_transaction` (full payload stored on-chain, `payload_hash: option::none()`), and later any owner with enough approvals calls execute, `validate_multisig_transaction` is supposed to bind the executed payload to the approved one: [1](#0-0) 

- The hash-matching branch only runs `if (transaction.payload_hash.is_some())` — which is false for full-payload transactions, so it is skipped entirely.
- The full-payload-matching branch that would otherwise catch a substituted payload is gated by `features::abort_if_multisig_payload_mismatch_enabled()`:
```
if (features::abort_if_multisig_payload_mismatch_enabled()
    && transaction.payload.is_some()
    && !payload.is_empty()
) { assert!(payload == *stored_payload, ...) }
```
If that feature flag is not enabled on a given network/at a given point in time, an executing owner can supply an arbitrary `payload` at execution time and `validate_multisig_transaction` will not detect the mismatch. Execution then proceeds using the caller-supplied `provided_payload`/`executable` (not necessarily the one approved by the quorum) as confirmed in the VM caller: [2](#0-1) [3](#0-2) 

This is exactly the "approval validation accepting the wrong approval set" pivot: the multisig account resource records that *N owners approved payload A*, but the on-chain payload actually executed as the multisig signer can be payload B, decoupling approval from execution content.

### Impact Explanation
If reachable (i.e., on any deployment where `AbortIfMultisigPayloadMismatch` is disabled), a single owner who has accumulated the required approval count for *some* transaction proposal can execute a *different* entry function/arguments under the multisig account's authority — an unauthorized-transaction-under-wrong-approval-set condition. Since the multisig account often holds significant assets/authority, this is potentially critical if the flag is off. However, this is a caveat gated entirely on a feature flag's live status.

### Likelihood Explanation
**I could not confirm the current default/enabled status of `AbortIfMultisigPayloadMismatch` in this index** (the feature-flag enum definition, its numeric ID, and whether it's included in `default_features()`/already active on mainnet were not retrievable within the available searches — `features.move`'s flag list didn't return before the tool budget ran out, and `aptos_features.rs` matches were not opened). This is a critical unresolved fact: if this flag is already enabled by default on all live networks, this is not exploitable and is legacy dead code retained only for playback/compatibility (a known, already-mitigated issue, per the module's own compatibility-guard comment pattern), not a new finding. If it is *not* on by default, this is a live, high-severity admission bypass.

### Recommendation
Confirm via `types/src/on_chain_config/aptos_features.rs` and `aptos-move/framework/move-stdlib/sources/configs/features.move` whether `AbortIfMultisigPayloadMismatch` is included in the default/always-on feature set for all networks. If not universally enabled, either make the full-payload match check unconditional (remove the feature gate) or reject empty/mismatched payloads at execution instead of silently falling back to the caller-supplied payload.

### Proof of Concept
Not constructed — dependent on unresolved feature-flag default status above. Conceptually: (1) owner A creates a multisig tx with `create_transaction` for payload `X` (transfer to A); (2) owner B approves, reaching quorum; (3) owner A (or any owner) executes supplying payload `Y` (transfer larger amount to A) instead of `X`; if `AbortIfMultisigPayloadMismatch` is disabled, `validate_multisig_transaction` does not detect the substitution and `Y` executes under the multisig account's signer.

Given the unresolved feature-flag status, I cannot assert this holds with full confidence as a *new* live vulnerability — flag it as **unverified/likely mitigated-by-default** rather than a confirmed finding.

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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1349-1390)
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
