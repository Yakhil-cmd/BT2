### Title
Multisig transaction execution can bypass owner-approved payload when full payload is stored on-chain and `abort_if_multisig_payload_mismatch` is disabled - (File: aptos-move/framework/aptos-framework/sources/multisig_account.move)

### Summary
`multisig_account::validate_multisig_transaction`, invoked by the VM as the admission/prologue check for `MultisigTransaction` execution, only verifies that the payload supplied at execution time matches what the owners approved in two cases: (1) when only a hash was stored on-chain, or (2) when the full payload was stored *and* the feature flag `abort_if_multisig_payload_mismatch_enabled` is turned on. When the full payload is stored on-chain (the default/common path via `create_transaction`) and that feature flag is off, an executing owner can submit an arbitrary, different entry-function payload for execution and it will pass admission as long as the (unrelated) quorum/timelock checks pass, because none of `assert_transaction_exists`, `can_execute`/`can_be_executed`, or the timelock check ever compares the *provided* payload to the approved one in this configuration.

### Finding Description
`validate_multisig_transaction` is the prologue-time approval check for multisig-account transactions: [1](#0-0) 

The function performs:
1. Existence and owner checks.
2. Quorum/timelock checks (`can_execute`/`can_be_executed`, `can_execute_with_timelock`) — these only verify *how many* owners voted, not *what* they voted on.
3. If `transaction.payload_hash.is_some()` (i.e., the transaction was created with `create_transaction_with_hash`), it hashes the caller-provided `payload` and compares to the stored hash — enforcing binding.
4. Only if `features::abort_if_multisig_payload_mismatch_enabled()` is true **and** `transaction.payload.is_some()` **and** the caller-provided `payload` is non-empty does it compare the provided payload byte-for-byte to the on-chain stored payload.

When a transaction was created via `create_transaction` (the normal, gas-cheaper, full-payload path), `transaction.payload` is `Some(..)` and `transaction.payload_hash` is `None`: [2](#0-1) 

In that state, step 3 above never executes (hash is `None`), and step 4 only executes if the feature flag is enabled. If the flag is disabled, **no code path checks that the entry function actually being executed by the VM matches the one the owners approved**. The VM constructs `provided_payload` directly from the `TransactionExecutable` in the submitted `SignedTransaction` and passes it into this Move function as the `payload` argument: [3](#0-2) 

So any account that is a multisig owner can, after quorum is reached on *some* approved transaction, submit a `MultisigTransaction` execution request with a *completely different* entry function/module/arguments as `provided_payload`. Since none of the approval-binding checks fire (hash is `None`, and the byte-comparison is feature-gated off), `validate_multisig_transaction` succeeds and the arbitrary payload executes with the multisig account as signer.

### Impact Explanation
This breaks the core security invariant of the multisig approval model: "N-of-M owners must approve a *specific* action before it executes as the multisig account." With the gate disabled, any single owner who can get quorum (even if that quorum only ever approved a benign, unrelated action) can execute an arbitrary entry function as the multisig account — e.g., transferring funds, rotating auth keys, or adding/removing owners — without approval of that specific action from the other owners. This is unauthorized transaction execution under a signer set (the multisig account signer) that the caller does not have the individually-approved authority to invoke, matching the "approval validation accepting the wrong approval set" and "pre-validation mismatch that causes a transaction which should fail admission to execute and commit" criteria.

### Likelihood Explanation
Likelihood is contingent on the on-chain state of the `abort_if_multisig_payload_mismatch_enabled` feature flag. If this flag is not yet enabled on a given network (it is guarded as a feature flag, implying rollout/gating), the bypass is trivially exploitable by any owner of any multisig account created with `create_transaction` (the default full-payload flow, as opposed to the gas-optimized `create_transaction_with_hash` flow, which is unaffected because it always hashes and checks the provided payload). No special privilege beyond being one of the multisig's owners is required, and multisig accounts are commonly used to hold significant value/authority (e.g., treasuries, governance), making this high-impact wherever the flag is off.

### Recommendation
Make the full-payload comparison unconditional (remove the `features::abort_if_multisig_payload_mismatch_enabled()` gate) so that whenever `transaction.payload.is_some()`, the provided payload is always required to exactly match the stored payload before proceeding, mirroring the unconditional hash check used in the `payload_hash` branch. If the feature flag exists purely for staged rollout/back-compat with older behavior, ensure it is enabled by default on all networks before this code path can be considered safe, and treat any network where it remains disabled as exposed.

### Proof of Concept
1. Owner A creates a multisig account `M` requiring 2-of-3 owners (A, B, C).
2. Owner A calls `create_transaction(A, M, payload_1)` where `payload_1` is a benign, harmless entry function (e.g., a no-op or trivial transfer of 1 octa) — this is stored as `MultisigTransaction { payload: Some(payload_1), payload_hash: None, .. }` per [2](#0-1) .
3. Owner B calls `approve_transaction(B, M, seq)`, reaching the 2-of-3 quorum for `payload_1`.
4. Owner A (or any owner) submits a `MultisigTransaction` execution with `transaction_payload = payload_evil` (e.g., "transfer all APT from M to attacker" or "rotate M's auth key"), which is entirely different from `payload_1`.
5. In `run_multisig_prologue`, the VM builds `provided_payload` from `payload_evil`'s executable and calls `validate_multisig_transaction(A, M, payload_evil_bytes)`: [3](#0-2) 
6. Inside `validate_multisig_transaction`: quorum check passes (2 approvals exist for the transaction record, regardless of what it approved), `transaction.payload_hash.is_some()` is false so no hash check runs, and if `abort_if_multisig_payload_mismatch_enabled()` is false, the byte-for-byte payload check is skipped entirely: [4](#0-3) 
7. `payload_evil` executes as the multisig account `M`, despite the owners never having approved it.

**Uncertainty note:** I could not fully determine the on-chain/default enabled status of `abort_if_multisig_payload_mismatch_enabled` from the indexed code (only the feature flag definition and its registration were located, not a definitive "enabled at genesis" or mainnet-resolution record). The exploitability of this finding is entirely contingent on that flag being disabled on the target network; if the network guarantees the flag is always on, this specific path is not exploitable. This should be verified against actual chain state before treating this as an active, unconditional vulnerability.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1163-1183)
```text
    /// Create a multisig transaction, which will have one approval initially (from the creator).
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
