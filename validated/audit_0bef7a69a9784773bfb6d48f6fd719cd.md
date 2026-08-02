Based on my investigation, the strongest local analog I found sits in the Aptos multisig transaction admission flow, not in the sequence-number/gas-payer prologue (which is well-hardened) or in the AA/derivable-account paths (explicitly out of scope).

### Title
Multisig transaction payload substitution bypasses owner-approved payload when `abort_if_multisig_payload_mismatch` is disabled - (File: `aptos-move/framework/aptos-framework/sources/multisig_account.move`)

### Summary
`multisig_account::validate_multisig_transaction`, the function invoked by the VM as part of transaction prologue/admission for `MultisigTransaction` payloads, only enforces that the *executor-supplied* payload matches the payload that owners actually approved on-chain when a non-default feature flag (`abort_if_multisig_payload_mismatch_enabled`) is turned on. When a transaction was created via `create_transaction` (full payload stored on-chain) rather than `create_transaction_with_hash`, and the feature flag is off, the code path that would compare the supplied payload against the stored payload is skipped entirely.

### Finding Description
`create_transaction` stores the full payload on-chain in `MultisigTransaction.payload`, and owners vote to approve/reject based on that stored payload [1](#0-0) . At execution time, the VM calls `validate_multisig_transaction(owner, multisig_account, payload)`, where `payload` is supplied fresh by the executing caller rather than read exclusively from chain state [2](#0-1) . The function checks quorum and timelock, then conditionally verifies payload integrity: [3](#0-2) 

The `payload_hash` branch only applies to transactions created via `create_transaction_with_hash`. For transactions created via `create_transaction` (full payload on-chain), the only check that the executor's supplied `payload` matches the on-chain-approved `transaction.payload` is gated by `features::abort_if_multisig_payload_mismatch_enabled()`. If that feature is disabled (or not yet activated on a given network), an owner who has (or can accumulate) enough approvals to satisfy quorum for sequence number N can execute with an arbitrary `payload` argument that was never seen or approved by the other owners, and `validate_multisig_transaction` will not reject it.

### Impact Explanation
This breaks the core invariant of the multisig admission model: "transaction execution will first check with this module that the transaction payload has gotten enough signatures" [4](#0-3) . If the mismatch check is not active, the quorum of approvals is bound to nothing — an executing owner can substitute any entry-function payload (e.g., draining funds, transferring ownership, arbitrary module calls as the multisig signer) while the on-chain approval trail still shows the *other*, benign payload was approved. This is exactly the class of "approval validation accepting the wrong approval set" called out in the admission pivots.

### Likelihood Explanation
Exploitation requires the executor to already be an owner with enough approvals under the multisig scheme (not an arbitrary unprivileged attacker), which lowers likelihood relative to a fully unauthenticated bug, but it still represents privilege escalation within the intended trust boundary (an owner authorized only to execute the *approved* payload can execute an *unapproved* one). Critically, I was unable to fully confirm within this session whether `abort_if_multisig_payload_mismatch_enabled` is enabled by default on current mainnet/testnet governance state, or whether it is a recently-introduced fix that is not yet universally activated — this is the key unresolved factor affecting real-world exploitability, and I could not verify it with the tools available in this session.

### Recommendation
Make the on-chain-payload equality check in `validate_multisig_transaction` unconditional (remove the feature-flag gate) whenever `transaction.payload.is_some()`, so a stored full payload is always cross-checked against the payload supplied at execution time, matching the guarantee already provided for hash-based transactions.

### Proof of Concept
1. Owner A creates a multisig transaction with `create_transaction(owner_A, multisig_addr, payload_benign)`, which owners B and C review off-chain and approve via `approve_transaction`.
2. Once quorum is met, owner A (or any owner with sufficient approvals) calls execute, but the underlying `SignedTransaction`'s `MultisigTransactionPayload` carries `payload_malicious` instead of `payload_benign`.
3. If `features::abort_if_multisig_payload_mismatch_enabled()` returns `false`, the branch at `aptos-move/framework/aptos-framework/sources/multisig_account.move:1375-1384` is skipped, `validate_multisig_transaction` succeeds, and `payload_malicious` executes as the multisig account signer — despite never having been voted on.

**Caveat:** Because I could not verify the default/rollout state of `abort_if_multisig_payload_mismatch_enabled` on live networks in this session, treat this as a code-level finding requiring confirmation of feature-flag activation status before assuming live exploitability.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L28-31)
```text
/// 5. If there are enough approvals, any owner can execute the transaction using the special MultisigTransaction type
/// with the transaction id if the full payload is already stored on chain or with the transaction payload if only a
/// hash is stored. Transaction execution will first check with this module that the transaction payload has gotten
/// enough signatures. If so, it will be executed as the multisig account. The owner who executes will pay for gas.
```

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

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1328-1334)
```text
    fun validate_multisig_transaction(
        owner: &signer, multisig_account: address, payload: vector<u8>) {
        assert_multisig_account_exists(multisig_account);
        assert_is_owner(owner, multisig_account);
        let sequence_number = last_resolved_sequence_number(multisig_account) + 1;
        assert_transaction_exists(multisig_account, sequence_number);

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
