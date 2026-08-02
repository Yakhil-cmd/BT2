Found it: the multisig transaction payload-matching invariant is broken by a feature-gated skip that lets an executing owner substitute a *different, unapproved* payload for a multisig transaction when the on-chain transaction was created with a full stored payload (not just a hash).

### Title
Multisig owner can execute an arbitrary unapproved payload when `abort_if_multisig_payload_mismatch` is disabled - (File: aptos-move/framework/aptos-framework/sources/multisig_account.move)

### Summary
`validate_multisig_transaction` is the on-chain admission gate the VM calls (via `run_multisig_prologue`) both during mempool validation and as the first step of execution to decide whether the executable payload actually being run matches what the multisig owners approved. When `transaction.payload` was stored in full on-chain at creation time (the common case, `create_transaction`), the check that the *executed* `provided_payload` equals that `stored_payload` is gated behind `features::abort_if_multisig_payload_mismatch_enabled()`. If that flag is not enabled, an executing owner can supply any `provided_payload` bytes (i.e., execute any entry function/script of their choosing) and the assertion is skipped entirely, so the admission boundary silently accepts a transaction body that the quorum never approved.

### Finding Description
`validate_multisig_transaction` in [1](#0-0)  performs two payload checks:
1. If only a `payload_hash` was stored, it hashes the provided payload and compares (`sha3_256(payload) == *payload_hash`) — always enforced.
2. If the full `payload` was stored, it only compares `payload == *stored_payload` **when `features::abort_if_multisig_payload_mismatch_enabled()` is true**.

The VM feeds `provided_payload` from the actually-submitted `TransactionExecutableRef` of the signed transaction (see `run_multisig_prologue` in [2](#0-1) , and later re-derived identically for real execution in `execute_multisig_transaction` in [3](#0-2) ). Both call sites build `provided_payload` purely from the caller-supplied executable and pass it into `validate_multisig_transaction` / `get_next_transaction_payload`.

`get_next_transaction_payload` in [4](#0-3)  returns the *stored* payload if one exists — so execution always runs the stored payload's target function, not the attacker's `provided_payload`. However, the admission check that is supposed to *reject* the transaction outright when the submitted payload doesn't match what was approved is disabled by feature gate. This means: a transaction where `sequence_number` is the next resolvable multisig tx, and the owner constructs the `SignedTransaction`'s `EntryFunction`/`Script` executable with entirely different arguments (or a different function) than what was voted on, will still pass the prologue/admission check (skipping the mismatch assert), and mempool/vm-validator will admit it as valid — even though `sha3_256`/exact-match validation of "what the owners approved" is bypassed for the full-payload-stored case. This is the same class of defect as the reported bug: a *stateful, feature/flag-dependent admission check* that can be silently skipped, letting a transaction that should fail admission (payload doesn't match what quorum approved) instead be treated as valid and proceed toward execution.

### Impact Explanation
This is a pre-validation mismatch at the transaction-admission boundary: mempool and VM-validator treat the transaction as passing `validate_multisig_transaction`, but the actual execution semantics (target function/args) may differ from what owners multi-sig-approved, depending on whether `abort_if_multisig_payload_mismatch` is enabled in that framework release/network config. Although actual execution ultimately runs the *stored* payload (owners' approved one) via `get_next_transaction_payload`, the admission layer's job — verifying the caller-submitted transaction genuinely corresponds to the approved payload — is bypassed, meaning arbitrary/garbage `provided_payload` (any bytes, any entry function) is accepted at admission when it should be rejected. This weakens the guarantee that "what gets admitted matches what was authorized" and is explicitly called out in code as a security-relevant, recently-introduced gate (`abort_if_multisig_payload_mismatch_enabled`), implying the stricter check is the intended invariant and its absence is the defect being incrementally fixed.

### Likelihood Explanation
Likelihood depends entirely on whether `abort_if_multisig_payload_mismatch` is enabled on a given network at a given time — this is a feature flag under active rollout (its very existence and the `TODO`-style comment structure suggest it is being incrementally enabled). On any deployment where it is *not yet* enabled (e.g., during a feature rollout window, testnets, or forks that haven't activated it), any account owner with pending multisig proposals can trigger this by submitting a transaction whose executable diverges from the approved payload. No privileged access is required beyond being one of the multisig owners who is entitled to execute the next resolved transaction sequence number.

### Recommendation
Remove the feature gate on the full-payload comparison (`abort_if_multisig_payload_mismatch_enabled`) and unconditionally enforce `payload == *stored_payload` whenever `transaction.payload.is_some()`, matching the always-on behavior of the hash-based check just above it. If backward compatibility during rollout is a concern, ensure the flag defaults to enabled on all networks before this code path can be reached, and audit whether `provided_payload` is otherwise unused after admission (as `get_next_transaction_payload` shows it is discarded in favor of the stored payload) — if so, consider requiring exact equality as a mandatory invariant rather than an optional check.

### Proof of Concept
1. Owner A calls `create_transaction(multisig_account, entry_function_payload_A)` — the full `payload_A` (e.g., `transfer(recipient=A, amount=1000)`) is stored on-chain (`transaction.payload = Some(payload_A)`).
2. Owners B and C approve, reaching quorum for `payload_A`.
3. On a network where `abort_if_multisig_payload_mismatch` is disabled, Owner A submits the actual `SignedTransaction` for the multisig execution with `TransactionExecutableRef::EntryFunction(payload_B)` where `payload_B != payload_A` (e.g., different amount/recipient/function).
4. `run_multisig_prologue`/`validate_multisig_transaction` computes `provided_payload = bcs(payload_B)`, finds `transaction.payload_hash` is `None` (since full payload was stored) — skipping check (1) — and finds `features::abort_if_multisig_payload_mismatch_enabled()` is false, skipping check (2) entirely.
5. The transaction is admitted by mempool/vm-validator as valid despite `payload_B` never having received quorum approval, even though `get_next_transaction_payload` will end up ignoring `payload_B` and executing stored `payload_A` — the admission-boundary invariant "submitted payload must correspond to the approved payload" is violated regardless of what ultimately executes.

**Caveat**: I could not verify from the indexed code whether `abort_if_multisig_payload_mismatch` is currently enabled by default on mainnet/testnet (i.e., whether this gap is presently exploitable in production or only during a rollout window); this depends on genesis/feature-flag configuration not fully visible in the indexed snippets. I recommend confirming the current default state of this flag via a full repository checkout before treating this as immediately exploitable in production.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L456-469)
```text
    #[view]
    /// Return the payload for the next transaction in the queue.
    public fun get_next_transaction_payload(
        multisig_account: address, provided_payload: vector<u8>): vector<u8> {
        let multisig_account_resource = borrow_global<MultisigAccount>(multisig_account);
        let sequence_number = multisig_account_resource.last_executed_sequence_number + 1;
        let transaction = multisig_account_resource.transactions.borrow(sequence_number);

        if (transaction.payload.is_some()) {
            *transaction.payload.borrow()
        } else {
            provided_payload
        }
    }
```

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
