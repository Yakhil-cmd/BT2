Confirmed: `ABORT_IF_MULTISIG_PAYLOAD_MISMATCH` (feature id 70) is **not** present in `default_features()` in `types/src/on_chain_config/aptos_features.rs`, meaning it is disabled by default unless explicitly enabled on a given chain/network via governance. This directly gates the missing-verification path found below.

### Title
Multisig transaction execution accepts a different payload than what owners approved when full payload is stored on-chain and `ABORT_IF_MULTISIG_PAYLOAD_MISMATCH` is disabled - (File: `aptos-move/framework/aptos-framework/sources/multisig_account.move`)

### Summary
`multisig_account::create_transaction` stores the full approved payload on-chain (`transaction.payload = Some(payload)`, `payload_hash = None`). At execution time, `validate_multisig_transaction` only cross-checks the caller-supplied payload against the stored payload when `payload_hash.is_some()` (the hash-only path) or when the `abort_if_multisig_payload_mismatch_enabled` feature is on. When a transaction was created with the full payload (not the hash-only variant) and this feature is disabled, an executing owner can submit an arbitrary, different `EntryFunction`/payload at execution time and it will run as the multisig account, without the quorum-approved payload ever being verified against what is actually executed.

### Finding Description [1](#0-0) 

`validate_multisig_transaction` is the VM-invoked prologue check for multisig execution:
- If `transaction.payload_hash.is_some()` (created via `create_transaction_with_hash`), the SHA3-256 of the caller-provided `payload` bytes must match the stored hash — this path is always enforced.
- If `transaction.payload.is_some()` (created via `create_transaction`, i.e., full payload stored on-chain), the match between the caller-provided payload and the on-chain-approved payload is **only checked when `features::abort_if_multisig_payload_mismatch_enabled()` is true**: [2](#0-1) 

This feature flag is absent from `FeatureFlag::default_features()`: [3](#0-2) 

On the VM side, the "provided payload" for an EntryFunction executable is derived directly from the executable the sender includes in the raw transaction (`bcs::to_bytes(&MultisigTransactionPayload::EntryFunction(entry_function))`), which is fully attacker-controlled and independent from whatever was approved by the owners: [4](#0-3) 

The actual dispatch to `GET_NEXT_TRANSACTION_PAYLOAD` in `execute_multisig_transaction` similarly threads the same unchecked `provided_payload` through to determine what gets executed: [5](#0-4) 

Net effect: with the feature disabled (its default state), quorum approval on a `MultisigTransaction` created via `create_transaction` (full-payload-on-chain) does not bind the approvers' votes to a specific payload at execution time for entry-function/script transactions submitted with a non-empty executable — only the hash-only creation path (`create_transaction_with_hash`) is unconditionally protected.

### Impact Explanation
This breaks the core "approval set → executed payload" binding invariant of multisig admission: any owner (not necessarily privileged beyond ordinary owner status) who has legitimately gathered enough approvals to execute sequence number N can, at execution time, substitute a different `EntryFunction`/`Script` payload of their choosing and have it executed and committed as the multisig account. This is unauthorized execution under the multisig account's authority with a payload the other owners never approved — a high-severity approval/authenticator confusion at the admission boundary, matching the "Authenticator/multisig approval validation accepting the wrong approval set" pivot in scope.

### Likelihood Explanation
Likelihood is high wherever a chain/network has not turned on `ABORT_IF_MULTISIG_PAYLOAD_MISMATCH`, since it ships disabled by default and any owner of any k-of-n multisig account using `create_transaction` (the plain, most commonly documented flow, as opposed to `create_transaction_with_hash`) can exploit it unilaterally once quorum is reached, without needing any other owners' cooperation or any additional secret material.

### Recommendation
Make the payload-match check for the full-payload-on-chain path unconditional (remove the `abort_if_multisig_payload_mismatch_enabled` gate), mirroring the unconditional hash check already used for `create_transaction_with_hash`, or enable `ABORT_IF_MULTISIG_PAYLOAD_MISMATCH` by default/via required governance activation before this code path is reachable on any live network.

### Proof of Concept
1. Owner A creates a multisig account with `create(..., num_signatures_required = 2, ...)` and owners `[A, B]`.
2. Owner A calls `create_transaction(A, multisig_addr, payload_X)` where `payload_X` calls a benign entry function (e.g., transfer 1 APT to C).
3. Owner B calls `approve_transaction(B, multisig_addr, seq)`, reaching the 2-of-2 quorum for `payload_X`.
4. Owner A now submits the actual on-chain `MultisigTransaction` execution transaction, but sets its `EntryFunction` executable to `payload_Y` (e.g., drain multisig funds to A's own address) instead of `payload_X`.
5. Because `ABORT_IF_MULTISIG_PAYLOAD_MISMATCH` is not in `default_features()`, `validate_multisig_transaction` skips the `payload == *stored_payload` check (the `transaction.payload_hash.is_some()` branch is false since this transaction used `create_transaction`, not `create_transaction_with_hash`), and `payload_Y` executes as the multisig account despite only `payload_X` having been approved.

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

**File:** types/src/on_chain_config/aptos_features.rs (L95-95)
```rust
    ABORT_IF_MULTISIG_PAYLOAD_MISMATCH = 70,
```

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L430-452)
```rust
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
