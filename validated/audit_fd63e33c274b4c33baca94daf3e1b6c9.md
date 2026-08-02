### Title
Multisig payload mismatch is only enforced under a feature flag, allowing an approved-but-unenforced payload swap - ([File: aptos-move/framework/aptos-framework/sources/multisig_account.move])

### Summary
`validate_multisig_transaction`, the function invoked by the VM prologue to admit a multisig transaction for execution, verifies quorum/timelock but only conditionally verifies that the payload actually being executed matches the payload the owners voted on [1](#0-0) . When a multisig transaction is created with `create_transaction` (full payload stored on-chain, `payload_hash = none`), the on-chain stored payload is only compared against the payload provided at execution time if `features::abort_if_multisig_payload_mismatch_enabled()` is on [2](#0-1) . If that feature is not enabled, the executing owner can substitute an arbitrary `executable` payload for the vote that was actually approved by the multisig quorum.

### Finding Description
`create_transaction` stores the full payload on-chain in `transaction.payload` with `payload_hash = option::none()` [3](#0-2) . Owners vote to approve this specific transaction via `vote_transanction`/`approve_transaction` [4](#0-3) .

At execution time, the VM calls `run_multisig_prologue`, which serializes the caller-supplied `executable` (from the actual transaction being submitted, not from chain state) into `provided_payload` and passes it into `validate_multisig_transaction` [5](#0-4) .

Inside `validate_multisig_transaction`, quorum and timelock are checked against the sequence number, but the check that the *provided* payload equals the *stored* payload is split into two branches:
- If `transaction.payload_hash.is_some()` (hash-only creation path), the SHA3-256 hash of the provided payload is always checked [6](#0-5) .
- If instead the full payload was stored (`transaction.payload.is_some()`, the common `create_transaction` path), the equality check between `payload` (provided) and `stored_payload` is only performed **when the feature `abort_if_multisig_payload_mismatch_enabled` is turned on** [2](#0-1) .

This means the binding between "what the owners approved" (the stored `payload`) and "what actually executes" (the `provided_payload` derived from the submitted transaction's executable) is not an unconditional invariant of the admission logic — it depends entirely on a feature-gate. As long as that feature is not active on a given network/version, any owner who has accumulated enough approvals to execute sequence number N can submit an execution transaction with a completely different entry-function payload than the one that was actually voted on, and it will pass `validate_multisig_transaction` and be executed by the VM.

### Impact Explanation
This breaks the core multisig admission invariant that execution must correspond to the specific approval set/payload that reached quorum — analogous to an authenticator/approval-set binding failure at the admission boundary. A single owner (who may hold much less than full control, e.g., 1 of N signers of a low-threshold multisig, or any owner acting alone after obtaining approvals for an innocuous-looking payload) could get quorum on a harmless-looking transaction and then execute an entirely different, malicious payload (e.g., draining funds or transferring capabilities) under the same approved sequence number, since nothing at the prologue level checks the swap in that code path when the flag is off.

### Likelihood Explanation
Likelihood depends on the current enablement state of the `abort_if_multisig_payload_mismatch_enabled` feature flag, which I could not conclusively verify from the indexed files (I found the feature definition/gating logic and its usage sites in `multisig_account.move`, `aptos_vm.rs`, and `transaction_validation.rs`, but not a clear, indexed record of its default/genesis enablement state for mainnet). This is an important caveat: if the flag is enabled by default on the target network, the mismatch path is closed and this is not exploitable; if it is disabled or only selectively rolled out, the gap is live. Given the existence of the conditional and the explicit feature-flag design pattern (used throughout this file for staged rollouts), it is plausible that some deployments/historical states have this check disabled.

### Recommendation
Make the provided-vs-stored payload equality check for the full-payload path (`transaction.payload.is_some()`) unconditional, removing the feature-flag gate, so that admission of a multisig transaction always enforces "executed payload == approved payload" regardless of feature rollout status. If backward compatibility requires staged rollout, ensure the flag is enabled on all live networks before considering this hardening complete, and add an explicit test that a mismatched payload is rejected when the flag is disabled.

### Proof of Concept
Conceptual reproduction (pending confirmation of feature-flag state on the target network):
1. Owner A calls `create_transaction(owner, multisig_addr, payload_benign)` — this stores `payload = Some(payload_benign)`, `payload_hash = None` [3](#0-2) .
2. Owners B, C vote to approve via `approve_transaction`, reaching quorum for `payload_benign`.
3. Owner A submits an actual on-chain `MultisigTransaction` whose `executable` encodes `payload_malicious` instead.
4. `run_multisig_prologue` computes `provided_payload = bcs(payload_malicious)` and calls `validate_multisig_transaction` [7](#0-6) .
5. Because `transaction.payload_hash.is_none()`, the hash check is skipped; because `abort_if_multisig_payload_mismatch_enabled()` is (hypothetically) false, the payload-equality check is also skipped [2](#0-1) .
6. The VM proceeds to execute `payload_malicious`, even though only `payload_benign` was ever approved by quorum.

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

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1210-1253)
```text
    /// Approve a multisig transaction.
    public entry fun approve_transaction(
        owner: &signer, multisig_account: address, sequence_number: u64) {
        vote_transanction(owner, multisig_account, sequence_number, true);
    }

    /// Reject a multisig transaction.
    public entry fun reject_transaction(
        owner: &signer, multisig_account: address, sequence_number: u64) {
        vote_transanction(owner, multisig_account, sequence_number, false);
    }

    /// Generic function that can be used to either approve or reject a multisig transaction
    /// Retained for backward compatibility: the function with the typographical error in its name
    /// will continue to be an accessible entry point.
    public entry fun vote_transanction(
        owner: &signer, multisig_account: address, sequence_number: u64, approved: bool) {
        assert_multisig_account_exists(multisig_account);
        let multisig_account_resource = borrow_global_mut<MultisigAccount>(multisig_account);
        assert_is_owner_internal(owner, multisig_account_resource);

        assert!(
            multisig_account_resource.transactions.contains(sequence_number),
            error::not_found(ETRANSACTION_NOT_FOUND),
        );
        let transaction = multisig_account_resource.transactions.borrow_mut(sequence_number);
        let votes = &mut transaction.votes;
        let owner_addr = address_of(owner);

        if (votes.contains_key(&owner_addr)) {
            *votes.borrow_mut(&owner_addr) = approved;
        } else {
            votes.add(owner_addr, approved);
        };

        emit(
            Vote {
                multisig_account,
                owner: owner_addr,
                sequence_number,
                approved,
            }
        );
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
