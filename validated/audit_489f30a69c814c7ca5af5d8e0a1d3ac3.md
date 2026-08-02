## Summary

Investigating the "missing repayment step" bug class (a state-mutating side effect skipped after an approval-gated action) against Aptos transaction-admission code, I found an analogous gap in the **multisig transaction execution/validation path**: the payload that is cryptographically approved by the multisig owners is not always the payload that actually gets executed on-chain.

### Finding Description

When a multisig transaction is created with a full payload via `create_transaction` (as opposed to `create_transaction_with_hash`), the `MultisigTransaction` struct stores the payload in `transaction.payload` and leaves `transaction.payload_hash` as `option::none()` (mirroring the complementary pattern seen in `create_transaction_with_hash`, which stores `payload_hash` and leaves `payload` as `option::none()`) [1](#0-0) .

At execution time, the VM builds a `provided_payload` from whatever `TransactionExecutableRef` is attached to the *outer* signed transaction that the executing owner submits — not from the stored `transaction.payload` — in both `run_multisig_prologue` and `execute_multisig_transaction`: [2](#0-1) [3](#0-2) 

This `provided_payload` is what is ultimately deserialized and actually executed with the multisig account's authority: [4](#0-3) [5](#0-4) 

The Move-level admission gate, `validate_multisig_transaction`, only cross-checks `provided_payload` against what was actually approved under two conditions:

1. If `transaction.payload_hash.is_some()` — always enforced (this is the `create_transaction_with_hash` path).
2. If `transaction.payload.is_some()` (the full-payload path) **AND** the feature flag `abort_if_multisig_payload_mismatch_enabled()` is on **AND** the caller-provided `payload` is non-empty: [6](#0-5) 

When `transaction.payload_hash` is `none()` (the normal case for `create_transaction`) and the `abort_if_multisig_payload_mismatch_enabled` feature is disabled — or the executing owner submits an outer transaction whose executable is `TransactionExecutableRef::Empty`, which forces `provided_payload` to an empty vector, satisfying `!payload.is_empty()` being false and thus skipping the mismatch check — **no comparison is performed at all** between what the owners actually approved (`transaction.payload`) and what will be executed (`provided_payload`).

The name and phrasing of this flag (`abort_if_multisig_payload_mismatch_enabled`) strongly indicates it is a bolt-on mitigation added after the fact for a pre-existing gap: the *original* `validate_multisig_transaction` semantics for the full-payload creation path did not bind the executed payload to the approved one at all.

### Impact Explanation

If this feature flag is not enabled on a given network (or during any window before it is enabled), any single owner of a k-of-n multisig account who has cast enough approvals for *some* transaction sequence number can execute an **entirely different `EntryFunction`/`Script` payload** than the one the other owners reviewed and approved, because:
- `assert_is_owner` only checks the executor is *an* owner,
- the approval-count/timelock checks only verify quorum was reached for *the sequence number*, not for a specific payload,
- and the payload-binding check is either absent (`payload_hash` is `none`) or feature-gated off.

This breaks the core multisig admission invariant that "the payload approved by the owner set is the payload executed under the multisig account's signer" — a direct analog of the external report's "approval path exists, but the binding/settlement step that ties the approved resource back to what is actually consumed is missing." Because multisig accounts often custody funds or hold privileged capabilities, a malicious or compromised single owner (with the ability to reach quorum count only for their own vote on that sequence number, e.g., in a 1-of-n or when they can accumulate/replay approvals for an unrelated payload of the same sequence number) can redirect multisig-authorized execution to arbitrary code, escalating from "approved action" to "unapproved arbitrary action" under the account's authority.

### Likelihood Explanation

This requires: (1) a multisig account created via the full-payload `create_transaction` path (the common case, since `create_transaction_with_hash` is the less-used privacy-preserving variant), and (2) the `abort_if_multisig_payload_mismatch_enabled` feature to be disabled, or the attacker submitting an empty executable. I could not verify from the available index whether this feature is enabled by default on Aptos mainnet today — this is the main open uncertainty. If it is already enabled everywhere, the exposure is closed; if it is still an opt-in/governance-controlled flag with a default of `false`, the gap is live for any multisig account on any chain that hasn't explicitly turned it on.

### Recommendation

- Make the full-payload equality check (`payload == *stored_payload`) unconditional whenever `transaction.payload.is_some()`, regardless of the `abort_if_multisig_payload_mismatch_enabled` flag and regardless of whether the caller-provided `payload` is empty (an empty caller payload against a non-empty stored payload should itself be treated as a mismatch, not silently skipped).
- Alternatively, always require `provided_payload` to be re-derived from `transaction.payload` when it is present, rather than trusting the executable field of the outer transaction, eliminating the divergence entirely.
- Ensure `PROLOGUE`/admission-time behavior and execution-time behavior use the exact same `provided_payload` derivation so there is no window where the two disagree.

### Proof of Concept

1. Owner A creates a multisig transaction via `create_transaction(owner_a, multisig_addr, entry_function_transfer_1_APT_to_owner_a)`. This stores `payload = some(bcs(EntryFunction::transfer_1_APT_to_owner_a))`, `payload_hash = none()`.
2. Owners B and C review the *sequence number* and approve it (standard UX: they may only see a summary, or in an automated/off-chain approval flow they approve by sequence number rather than re-verifying the raw payload bytes each time), reaching the k-of-n threshold.
3. On a network/state where `abort_if_multisig_payload_mismatch_enabled` is disabled, Owner A submits the actual execution transaction with a **different** executable, e.g. `EntryFunction::transfer_all_APT_to_owner_a`, or wraps it so the outer executable is empty (`TransactionExecutableRef::Empty`), which forces `provided_payload = vec![]`.
4. `validate_multisig_transaction` finds `payload_hash.is_none()`, skips the hash check; finds either the mismatch-feature disabled or `payload.is_empty()`, skips the full-payload equality check.
5. `execute_multisig_transaction` deserializes `provided_payload` (the attacker-chosen bytes, not the approved ones) and executes it under the multisig account's signer, transferring more funds than approved.

Note: I was unable to fully confirm the mainnet/default activation state of `abort_if_multisig_payload_mismatch_enabled` from the indexed code, which materially affects present-day exploitability; this should be verified directly against `aptos-move/framework/move-stdlib/sources/configs/features.move` and the deployed feature-flag state before treating this as actively exploitable on a live network.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1201-1207)
```text
            payload: option::none<vector<u8>>(),
            payload_hash: option::some(payload_hash),
            votes: simple_map::create<address, bool>(),
            creator,
            creation_time_secs: now_seconds(),
        };
        add_transaction(creator, multisig_account, transaction);
```

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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1300-1348)
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1387-1406)
```rust
        let payload_bytes =
            bcs::from_bytes::<Vec<u8>>(payload_bytes).map_err(|_| deserialization_error())?;
        let payload = bcs::from_bytes::<MultisigTransactionPayload>(&payload_bytes)
            .map_err(|_| deserialization_error())?;

        // Step 2: Execute the target payload. Transaction failure here is tolerated. In case of any
        // failures, we'll discard the session and start a new one. This ensures that any data
        // changes are not persisted.
        // The multisig transaction would still be considered executed even if execution fails.
        let execution_result = self.execute_multisig_payload(
            resolver,
            code_storage,
            session,
            gas_meter,
            traversal_context,
            multisig_address,
            &payload,
            change_set_configs,
            trace_recorder,
        );
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1486-1506)
```rust
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
