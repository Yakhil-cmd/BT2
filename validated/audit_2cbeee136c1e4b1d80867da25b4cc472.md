### Title
Multisig transaction execution can bypass approved-payload binding when `abort_if_multisig_payload_mismatch_enabled` is off - ([File: aptos-move/framework/aptos-framework/sources/multisig_account.move])

### Summary
`multisig_account::validate_multisig_transaction`, the VM-invoked prologue that gates execution of a pre-approved multisig transaction, only checks that the *executed* payload matches the payload that owners voted on when a feature flag (`abort_if_multisig_payload_mismatch_enabled`) is turned on. When a transaction was created via `create_transaction` (full payload stored on-chain, no hash), and that flag is disabled, the prologue performs **no comparison at all** between the payload the owners approved and the payload actually supplied at execution time. This breaks the "approval set binds to the executed code" invariant that is the entire point of a multisig account.

### Finding Description
Two ways to register a pending multisig transaction exist:
- `create_transaction` stores the full `payload` inline (`payload_hash = None`). [1](#0-0) 
- `create_transaction_with_hash` stores only a `sha3_256` hash (`payload = None`). [2](#0-1) 

At execution time, the VM calls `validate_multisig_transaction(owner, multisig_account, payload)` from `run_multisig_prologue`, where `payload` is derived from whatever `TransactionExecutableRef` the *executing* transaction actually contains (entry function or script bytes chosen by the caller, not looked up from chain state): [3](#0-2) 

Inside `validate_multisig_transaction`, quorum/timelock checks are performed, and then:
- If `payload_hash.is_some()` (the `create_transaction_with_hash` case), the hash is always checked against the caller-supplied payload — safe.
- If the transaction was created with `create_transaction` (`payload_hash.is_none()`, `payload.is_some()`), the match against the stored, owner-approved payload is only enforced **when `features::abort_if_multisig_payload_mismatch_enabled()` is true**: [4](#0-3) 

When that feature is disabled, `validate_multisig_transaction` returns success regardless of what `payload` was passed in. The prologue then allows the actual execution step, `execute_multisig_transaction` / `execute_multisig_payload`, to run whatever entry function or script the caller placed in the executing transaction's `TransactionExecutableRef` — completely independent of the payload that was originally created and voted on by the multisig owners: [5](#0-4) [6](#0-5) 

The prologue's approval-count logic (`num_approvals >= num_signatures_required`) is computed purely from the `sequence_number` slot, not from the payload contents, so quorum is satisfied by votes cast for the *original* payload while a *different* payload executes as the multisig account's signer.

### Impact Explanation
This allows any single owner who is entitled to invoke the multisig's next pending transaction slot to substitute an arbitrary, unapproved entry function or script for the one that other owners actually voted to approve, while still consuming/resolving that approved sequence number. Because the executed code runs with the multisig account's signer, an executing owner can drain funds, rotate keys, or perform any privileged action the multisig account is authorized to do — completely defeating the quorum/approval guarantee that is multisig's core security property. This is a critical admission-boundary bypass: "approval validation accepting the wrong approval set."

### Likelihood Explanation
The bypass requires the on-chain `abort_if_multisig_payload_mismatch_enabled` feature flag to be off for the relevant chain/network, and it only affects multisig transactions created via `create_transaction` (inline payload) rather than `create_transaction_with_hash`. Because this check is comment-documented as an added later hardening (the code and doc explicitly frame it as validating "if the transaction payload is stored on chain … verify that the provided payload matches"), it strongly suggests this protection did not always exist and remains conditional; on any deployment where the flag has not been enabled, the bypass is fully exploitable by a normal (non-privileged) multisig owner. I was unable to fully confirm the current default/enablement state of `abort_if_multisig_payload_mismatch_enabled` in this index (feature-flag defaults are typically set via genesis/release config, which I did not have full visibility into within the tool budget), so likelihood should be validated against actual mainnet/testnet feature-flag state before treating this as universally exploitable today.

### Recommendation
Remove the feature-flag gate and unconditionally enforce that, for transactions created with an inline `payload` (`transaction.payload.is_some()`), the executed payload must equal the stored payload, mirroring the unconditional hash check used for `payload_hash`. If backward compatibility requires a flag during rollout, ensure the flag is enabled by default on all networks and treat the unguarded path as a hard error rather than a silent skip.

### Proof of Concept
1. Owner A calls `multisig_account::create_transaction(owner_a, multisig_addr, payload_X)` where `payload_X` is a benign, approved operation. This stores `payload = Some(payload_X)`, `payload_hash = None` at the next sequence number. [1](#0-0) 
2. Other owners vote to approve based on `payload_X` until quorum (`num_signatures_required`) is reached.
3. On a chain where `abort_if_multisig_payload_mismatch_enabled` is disabled, owner A submits the actual on-chain execution transaction with `TransactionExecutableRef` containing a *different*, malicious entry function `payload_Y` (e.g., transferring all funds from the multisig account, or adding a new owner with full control).
4. `run_multisig_prologue` computes `provided_payload = bcs(payload_Y)` from the transaction's own executable and passes it into `validate_multisig_transaction`. Since `payload_hash` is `None` and the mismatch-check feature is off, the function returns without ever comparing `payload_Y` to the stored `payload_X`. [4](#0-3) 
5. `execute_multisig_transaction` proceeds to execute `payload_Y` (not `payload_X`) with the multisig account as signer, even though only `payload_X` was ever approved. [7](#0-6)

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1164-1183)
```text
    public entry fun create_transaction(
        owner: &signer,
        multisig_account: address,
        payload: vector<u8>,
    ) {
        assert!(payload.length() > 0, error::invalid_argument(EPAYLOAD_CANNOT_BE_EMPTY));

        assert_multisig_account_exists(multisig_account);
        assert_is_owner(owner, multisig_account);

        let creator = address_of(owner);
        let transaction = MultisigTransaction {
            payload: option::some(payload),
            payload_hash: option::none<vector<u8>>(),
            votes: simple_map::create<address, bool>(),
            creator,
            creation_time_secs: now_seconds(),
        };
        add_transaction(creator, multisig_account, transaction);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1185-1208)
```text
    /// Create a multisig transaction with a transaction hash instead of the full payload.
    /// This means the payload will be stored off chain for gas saving. Later, during execution, the executor will need
    /// to provide the full payload, which will be validated against the hash stored on-chain.
    public entry fun create_transaction_with_hash(
        owner: &signer,
        multisig_account: address,
        payload_hash: vector<u8>,
    ) {
        // Payload hash is a sha3-256 hash, so it must be exactly 32 bytes.
        assert!(payload_hash.length() == 32, error::invalid_argument(EINVALID_PAYLOAD_HASH));

        assert_multisig_account_exists(multisig_account);
        assert_is_owner(owner, multisig_account);

        let creator = address_of(owner);
        let transaction = MultisigTransaction {
            payload: option::none<vector<u8>>(),
            payload_hash: option::some(payload_hash),
            votes: simple_map::create<address, bool>(),
            creator,
            creation_time_secs: now_seconds(),
        };
        add_transaction(creator, multisig_account, transaction);
    }
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

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1300-1349)
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
        // Failures here will be propagated back.
```

**File:** aptos-move/aptos-vm/src/aptos_vm.rs (L1469-1506)
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
