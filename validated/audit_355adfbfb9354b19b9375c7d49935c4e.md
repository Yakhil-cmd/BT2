## Finding

Based on my investigation, I found a concrete admission-boundary vulnerability analog in the multisig transaction validation logic, though I want to flag upfront that I could not fully trace whether the executor-supplied payload (vs. the on-chain stored payload) is what the VM actually dispatches for execution — this is the one piece of uncertainty in this finding, discussed in the Likelihood section.

### Title
Multisig transaction payload substitution bypasses approval binding when `abort_if_multisig_payload_mismatch` feature is disabled - (File: `aptos-move/framework/aptos-framework/sources/multisig_account.move`)

### Summary
`validate_multisig_transaction` (invoked by the VM prologue for every multisig-executed transaction) only verifies that the executor-provided payload bytes match the on-chain approved transaction in two cases: (1) when the transaction was created via `create_transaction_with_hash` (payload_hash path — checked unconditionally), and (2) when created via `create_transaction` (full payload stored on-chain) **only if** the feature `abort_if_multisig_payload_mismatch_enabled` is turned on.

### Finding Description [1](#0-0) 

```
if (transaction.payload_hash.is_some()) {
    assert!(sha3_256(payload) == *payload_hash, ...);
};
if (features::abort_if_multisig_payload_mismatch_enabled()
    && transaction.payload.is_some()
    && !payload.is_empty()
) {
    let stored_payload = transaction.payload.borrow();
    assert!(payload == *stored_payload, ...)
}
```

Owners approve/reject a multisig transaction against the on-chain `MultisigTransaction.payload` field [2](#0-1) . Voting (`approve_transaction`/`vote_transanction`) records only a boolean vote keyed to a sequence number — it never re-checks the payload bytes at vote time either [3](#0-2) . The binding between "what owners voted for" and "what actually executes" depends entirely on the payload-equality assertion quoted above.

For the common `create_transaction` (full-payload) path, that binding check is feature-gated behind `abort_if_multisig_payload_mismatch_enabled`, which is a togglable AIP-style on-chain feature flag [4](#0-3) . If that flag is not activated on a given network, any owner who has enough approvals to satisfy the k-of-n quorum for sequence number N can submit an execution transaction (`TransactionPayload::Multisig`) whose `transaction_payload` bytes differ arbitrarily from the payload that was actually approved on-chain, and `validate_multisig_transaction` will not detect the mismatch — the `!payload.is_empty()` / feature check simply skips the assertion.

### Impact Explanation
If the executor-supplied payload is what gets dispatched for actual execution (rather than the VM independently re-reading and re-executing `transaction.payload` from storage), this breaks the core multisig invariant: "only owners are allowed to execute a valid transaction... if the number of approvals meets the k-of-n criteria," documented as a Critical-severity audit requirement [5](#0-4) . A single owner (or a colluding minority) could get co-owners to approve an innocuous-looking payload (e.g., a small transfer) and then execute a completely different, unapproved payload (e.g., draining funds, changing owners, rotating keys) — an approval-set/authenticator confusion at the transaction-admission boundary, matching the required "wrong approval set" impact class.

### Likelihood Explanation
This is feature-gated and I was unable to confirm from the available index whether `abort_if_multisig_payload_mismatch_enabled` defaults to on or off on current mainnet, nor could I trace the exact execution-dispatch code path in `aptos-move/aptos-vm/src/aptos_vm.rs` that consumes the multisig payload to confirm definitively that it uses the executor-supplied bytes (rather than always re-fetching `transaction.payload` from chain state for full-payload transactions). If the VM always executes the on-chain stored payload regardless of what's passed at the transaction layer, this check would be defense-in-depth only and not independently exploitable. Given the existence of a dedicated feature flag purpose-built to add this specific equality assertion, it's likely this class of issue was previously identified and is being phased in via governance — meaning the risk window exists specifically for deployments where the flag has not yet been enabled.

### Recommendation
Make the payload-equality check for the full-payload (`create_transaction`) path unconditional (not gated behind a feature flag), matching the unconditional hash-check behavior of `create_transaction_with_hash`. If the flag exists for phased rollout reasons, ensure it is enabled network-wide before any multisig account can safely rely on `create_transaction`.

### Proof of Concept
Not independently reproducible from the indexed code alone — a full PoC would require: (1) confirming via `aptos-move/aptos-vm/src/aptos_vm.rs` that the multisig executable is invoked using the `transaction_payload` bytes carried in the outer `TransactionPayload::Multisig` (not the separately-stored `MultisigTransaction.payload`), and (2) confirming the on-chain state of `abort_if_multisig_payload_mismatch_enabled`. I could not complete this verification with the remaining tool budget, so this finding should be treated as a strong candidate requiring the above two confirmations before treating it as fully proven.

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

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1225-1253)
```text
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

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1360-1385)
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

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L1-1)
```text
/// Defines feature flags for Aptos. Those are used in Aptos specific implementations of features in
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.spec.move (L133-149)
```text
    /// No.: 15
    /// Requirement: Only owners are allowed to execute a valid transaction, if the number of approvals meets the k-of-n
    /// criteria, finally the executed transaction should be removed.
    /// Criticality: Critical
    /// Implementation: Functions execute_rejected_transaction and validate_multisig_transaction can only be called by
    /// the owner which validates the transaction and based on the number of approvals and rejections it proceeds to
    /// execute the transactions. For rejected transaction, the transactions are immediately removed from the
    /// MultisigAccount via remove_executed_transaction. VM validates the transaction via validate_multisig_transaction
    /// and cleans up the transaction via successful_transaction_execution_cleanup and
    /// failed_transaction_execution_cleanup.
    /// Enforcement: Audited that it aborts if the caller is not in the owner's list (execute_rejected_transaction,
    /// validate_multisig_transaction). Audited that it aborts if the transaction with the given sequence number doesn't
    /// exist in the account (execute_rejected_transaction, validate_multisig_transaction). Audited that it aborts if
    /// the votes (approvals or rejections) are less than num_signatures_required (execute_rejected_transaction,
    /// validate_multisig_transaction). Audited that the transaction is removed from the MultisigAccount
    /// (execute_rejected_transaction, remove_executed_transaction, successful_transaction_execution_cleanup,
    /// failed_transaction_execution_cleanup).
```
