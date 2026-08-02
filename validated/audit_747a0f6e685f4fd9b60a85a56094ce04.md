Based on my investigation, the strongest candidate is the payload-mismatch bypass in the multisig account's execution prologue, gated behind a feature flag that defaults to disabled unless explicitly enabled by governance.

### Title
Feature-gated payload verification allows execution of a different payload than the one approved by multisig owners - (File: aptos-move/framework/aptos-framework/sources/multisig_account.move)

### Summary
`validate_multisig_transaction`, the function invoked by the VM prologue during multisig transaction execution, only verifies that the executor-supplied `payload` matches the on-chain stored payload when the feature flag `abort_if_multisig_payload_mismatch_enabled()` is turned on. When this flag is disabled (its baseline/rollout state), an executing owner can supply an arbitrary `payload` argument that differs from the payload the other owners actually voted on, and the transaction will still execute using that unverified payload.

### Finding Description
When a multisig transaction is created via `create_transaction` (as opposed to `create_transaction_with_hash`), the full payload is stored on-chain in `transaction.payload`, and `transaction.payload_hash` is `None`. [1](#0-0) 

Owners vote/approve based on this stored payload via `approve_transaction`/`vote_transanction`, which only reference the `sequence_number`, not the payload content itself. [2](#0-1) 

At execution time, the VM calls `validate_multisig_transaction(owner, multisig_account, payload)`, where `payload` is supplied fresh by the executing owner as an argument to the special `MultisigTransaction` execution flow (not re-derived from the stored transaction record). The function checks quorum, timelock, and then attempts to validate the payload: [3](#0-2) 

- If `transaction.payload_hash.is_some()` (i.e., created via `create_transaction_with_hash`), the hash is always checked — this path is safe.
- If `transaction.payload` is `Some` (full payload stored on-chain, the `create_transaction` path), the match against the stored payload is **only enforced when `features::abort_if_multisig_payload_mismatch_enabled()` returns true**. When this feature is disabled, the `assert!(payload == *stored_payload, ...)` block is skipped entirely, and the supplied `payload` proceeds to execution unchecked against what was actually approved.

The framework's own audit table documents the intended invariant — "Only owners are allowed to execute a valid transaction, if the number of approvals meets the k-of-n criteria" — implicitly assuming the executed payload is the one that was approved, but this feature-gated check breaks that assumption whenever the flag is off. [4](#0-3) 

### Impact Explanation
This breaks the core admission invariant of the multisig module: that a transaction executed under the multisig account's authority is the exact payload that a quorum of owners approved. Any single owner (who is by definition an authorized but individually unprivileged party in a k-of-n multisig, e.g., 1-of-N in a k-of-n>1 setup) can construct a transaction with sequence number N containing an innocuous or minimal `create_transaction` payload (e.g., a benign transfer), get it approved by co-owners, and then execute it while substituting a different, malicious payload at the execution step — bypassing the quorum's actual intent. Because the multisig account is a resource account with elevated authority over its own funds/capabilities, this can lead to unauthorized fund transfers or arbitrary entry-function calls executed "as" the multisig account, without the required approval for the specific action taken.

### Likelihood Explanation
Exploitability depends entirely on the on-chain state of `abort_if_multisig_payload_mismatch_enabled` (an `std::features` flag). If it is disabled on a given network deployment (e.g., not yet rolled out via governance), any single owner with execution rights on a pending, quorum-approved transaction can trigger this bypass with no additional privilege — it only requires calling the standard execution entry point with a different payload than what was recorded on-chain. I was not able to independently confirm from the code alone whether this flag is enabled by default in the current mainnet/testnet genesis feature set (feature defaults are typically set via `on_chain_config`/genesis initialization outside the scope of what I could verify here), so the actual current-network exploitability is uncertain and depends on deployment configuration.

### Recommendation
Remove the feature gate on the payload-match check for full-payload multisig transactions (`transaction.payload.is_some()`), and always enforce that the executor-supplied `payload` equals the on-chain stored `transaction.payload` byte-for-byte whenever a stored payload exists (mirroring the unconditional `payload_hash` check). If the gate exists purely for backward-compatibility during rollout, ensure the flag is enabled network-wide before considering the fix complete, and treat "flag disabled" state as vulnerable during that window.

### Proof of Concept
Conceptual PoC (Move-level, requires the feature flag to be disabled):
```move
// Owner A creates a transaction with payload P1 (e.g., "transfer 1 APT to X").
create_transaction(owner_a, multisig_addr, P1);

// Owners B, C approve sequence_number = N based on reviewing P1.
approve_transaction(owner_b, multisig_addr, N);
approve_transaction(owner_c, multisig_addr, N);

// Owner A (or any owner with enough approvals) executes with an
// entirely different payload P2 (e.g., "transfer all funds to attacker").
// Because abort_if_multisig_payload_mismatch_enabled() == false,
// validate_multisig_transaction() skips the payload-match assert,
// and P2 is executed as the multisig account instead of the approved P1.
```

Note on confidence: This finding is derived purely from static code analysis of `multisig_account.move`; I could not execute the Move test suite or confirm the runtime/genesis default value of the `abort_if_multisig_payload_mismatch_enabled` feature flag in this environment, which is the deciding factor for whether this is currently exploitable on a live network.

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
