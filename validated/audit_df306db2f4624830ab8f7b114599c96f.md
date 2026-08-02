## Title
Multisig transaction payload substitution bypasses approval binding when `abort_if_multisig_payload_mismatch` is disabled — ([File: aptos-move/framework/aptos-framework/sources/multisig_account.move])

## Summary
`multisig_account::validate_multisig_transaction`, invoked by the VM as part of transaction admission/prologue for multisig executions, is supposed to guarantee that the payload being executed is exactly the payload the quorum of owners approved. For transactions created with a full stored payload (`transaction.payload = Some(...)`, `payload_hash = None`), that binding is only enforced when the feature flag `abort_if_multisig_payload_mismatch_enabled` is turned on. When it is off, an executing owner can submit any `payload`/`executable` at execution time and it is never compared against the on-chain stored payload, letting a transaction other than the one voted on be admitted and executed under the multisig's approval count.

## Finding Description
`validate_multisig_transaction` in <cite repo="Jaredbentat/aptos-core--024" path="aptos-move/framework/aptos-framework/sources/multisig_account.move" start="1328="/>only performs two payload-integrity checks:

1. If `transaction.payload_hash.is_some()` (hash-only creation path), it checks `sha3_256(payload) == payload_hash` — always enforced.
2. If `transaction.payload.is_some()` (full-payload creation path) **and** `features::abort_if_multisig_payload_mismatch_enabled()` is true, it checks `payload == stored_payload`. [1](#0-0) 

If the feature flag is disabled, the second check is skipped entirely for transactions that were created with a stored full payload. In that state, the caller-supplied `payload` (built by the VM from the `executable` field of the *submitted* signed transaction, not from the on-chain `MultisigAccount` state) is never validated against what owners actually approved: [2](#0-1) 

The VM then re-derives the payload to run from the same unauthenticated `provided_payload`/`GET_NEXT_TRANSACTION_PAYLOAD` return value in `execute_multisig_transaction`: [3](#0-2) 

Only the quorum count (`can_execute`/`can_be_executed`) and timelock are checked against the sequence number — not the content of what is executed. This is a violation of the "Authenticator, WebAuthn, multisig, or approval validation accepting the wrong signing material or wrong approval set" admission invariant: the approval set (owners' votes) was bound to sequence number `N`, but with the flag off there is no cryptographic or structural guarantee that the payload finally admitted for execution at sequence number `N` is the one the owners voted for.

## Impact Explanation
If exploitable, an owner (or any account with the ability to submit the multisig-transaction-execution call, since `assert_is_owner` only requires the caller to be *an* owner, not the one who created the transaction) can have the VM admit and execute an arbitrary entry function under the identity of the multisig account, while consuming the approvals that were cast for a completely different, presumably benign, transaction. This is a state-transition-under-wrong-approval-set class issue with potentially critical impact (arbitrary code execution as the multisig account, e.g., draining funds or transferring capabilities) if the feature gate defaults to disabled in the deployed environment.

## Likelihood Explanation
Exploitability is entirely gated by the on-chain value of the `abort_if_multisig_payload_mismatch` feature flag. I located the flag's definition and usages in `aptos-move/framework/move-stdlib/sources/configs/features.move` and `types/src/on_chain_config/aptos_features.rs`, but I was not able to confirm within the available tool budget whether this flag is enabled by default on current mainnet/testnet genesis, or whether it is still in a rollout/staged state. If the flag is already enabled everywhere, this path is not currently exploitable and the code path is dead in practice (this would need to be confirmed by inspecting the genesis feature defaults, e.g. `aptos-move/framework/aptos-framework/sources/configs/aptos_features.move` initialization or `cached_packages`/testnet genesis configs).

## Recommendation
- Remove the feature-flag gate on the payload/executable comparison for the full-payload creation path, or fail closed (require the check to always run) once the flag is fully rolled out.
- As a stronger structural fix, make `execute_multisig_transaction`/`validate_multisig_transaction` always derive the executed payload from the `MultisigAccount.transactions[sequence_number]` on-chain state (when `payload` is stored) rather than accepting a caller-supplied `payload`/`executable` that is only conditionally checked.
- Add an explicit e2e/unit test asserting that, with the feature disabled, execution with a payload of full a stored-payload transaction that differs from the approved one is rejected (currently there does not appear to be such a negative test guarding this specific flag-off branch based on what was inspected).

## Proof of Concept
Conceptual PoC (dependent on the flag being disabled on the target network):
1. Owner A calls `multisig_account::create_transaction(owner_a, multisig_addr, payload_A)` — a benign payload, e.g., transferring 1 APT — stored fully on-chain (`payload = Some(payload_A)`, `payload_hash = None`).
2. Owners B and C approve via `approve_transaction`, reaching quorum for sequence number `N`.
3. Owner A (or any owner) submits the actual on-chain "execute multisig transaction" transaction, but sets the transaction's `executable`/entry-function field to `payload_B` (e.g., transferring the entire balance to an attacker address) instead of `payload_A`.
4. `run_multisig_prologue`/`validate_multisig_transaction` checks quorum for sequence `N` (satisfied) and, because `payload_hash` is `None` and `abort_if_multisig_payload_mismatch_enabled()` is false, never checks `payload_B == payload_A`.
5. `execute_multisig_transaction` executes `payload_B` under the multisig account's signer, using the approvals that were cast for `payload_A`.

Note: This PoC's real-world exploitability hinges on the unresolved question of the feature flag's current default state, which should be verified before treating this as an immediately actionable finding.

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

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L429-460)
```rust
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1305-1390)
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
        // Failures here will be propagated back.
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
