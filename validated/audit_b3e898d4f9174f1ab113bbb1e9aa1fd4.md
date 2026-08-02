## Answer

Given the exploration, the strongest local analog I found is in the multisig transaction admission path, not the stableswap fee-skew pattern directly, but a similar "approval doesn't bind to what actually executes" invariant break.

### Title
Multisig transaction execution accepts a payload that does not match what owners approved when the payload mismatch feature flag is disabled - (File: aptos-move/framework/aptos-framework/sources/multisig_account.move)

### Summary
`create_transaction` stores the full payload on-chain but leaves `payload_hash` as `None` [1](#0-0) . During VM prologue validation, `validate_multisig_transaction` only cryptographically checks the executor-supplied `payload` against the stored `payload_hash` when `transaction.payload_hash.is_some()` [2](#0-1) . For the `create_transaction` path (`payload_hash == None`), the *only* remaining defense — comparing the executor's payload against the on-chain stored `transaction.payload` — is gated entirely behind the `abort_if_multisig_payload_mismatch_enabled()` feature flag [3](#0-2) .

### Finding Description
When owners vote to approve/reject a multisig transaction (`vote_transanction`), they vote only on a `sequence_number`, not on the payload content directly [4](#0-3) . The binding between "what owners voted for" and "what actually executes" is supposed to be enforced at prologue time in `validate_multisig_transaction`, which is invoked both during mempool validation and transaction execution [5](#0-4) .

That binding is only strict when the transaction was created via `create_transaction_with_hash` (payload stored off-chain, `payload_hash` on-chain) — in that case the executor-provided `payload` is checked via `sha3_256(payload) == *payload_hash`, an unconditional assert [6](#0-5) .

For the more common `create_transaction` path, the full payload is already stored on-chain (`transaction.payload = option::some(payload)`), and the comparison of the executor-supplied `payload` argument against that stored payload is wrapped in a feature-flag condition:
```
if (features::abort_if_multisig_payload_mismatch_enabled()
    && transaction.payload.is_some()
    && !payload.is_empty()
) { assert!(payload == *stored_payload, ...) }
``` [3](#0-2) 

If `abort_if_multisig_payload_mismatch_enabled()` is off (this is a rollout-style, opt-in feature flag per the module's flag-lifetime documentation conventions [7](#0-6) ), this comparison never runs. Consequently, once quorum approvals exist for a given `sequence_number` (`can_execute`/`can_be_executed`, verified against the *original* approved transaction) [8](#0-7) , any owner submitting the executing transaction can supply an entirely different `payload` at execution time and it will run — the sequence number's quorum was earned by owners voting on one payload, but the VM executes whatever payload the executor (an unprivileged single owner, not requiring re-approval) chooses to submit.

### Impact Explanation
This breaks the core multisig invariant documented in the module's own audit table: "the executed transaction should be removed" and "only owners with sufficient approvals can execute a valid transaction" — the *transaction*, not an arbitrary payload, is supposed to be what's authorized [9](#0-8) . Any of the k-of-n signers (or even the transaction creator alone if they can reach the required approval threshold through implicit self-approval and collusion) can substitute a completely unrelated payload — e.g., swap a "transfer $100 to Alice" approved transaction for "transfer all funds to attacker" — and have it execute using the same sequence number and vote count as the originally-approved, different transaction. This is a direct authorization/approval-set-binding failure at the admission boundary (prologue), matching "authenticator/approval validation accepting the wrong approval set" and "pre-validation mismatch that causes a transaction which should fail admission to execute."

### Likelihood Explanation
Likelihood depends entirely on whether `abort_if_multisig_payload_mismatch_enabled` is turned on network-wide. I was not able to confirm from the indexed content whether this flag is currently enabled on mainnet/testnet by default; the naming and structure (a flag explicitly gating a security-relevant equality check, requiring "approval of framework owners" per the module header) strongly suggests it was added later as a fix for exactly this gap and may not be universally enabled, or there may be a window during rollout where it is off. This is the key uncertainty in this finding — without confirming the flag's on-chain activation status, I cannot assert this is exploitable right now on a live Aptos network, only that the code path itself contains no defense-in-depth when the flag is off.

### Recommendation
Make the payload-vs-stored-payload check for `create_transaction`-created transactions unconditional (not feature-flag-gated), mirroring the unconditional hash check used for `create_transaction_with_hash`. If the flag exists purely for staged rollout/compatibility, ensure it is confirmed enabled on all networks before considering the code path safe, and eventually delete the flag per the stated feature-flag lifecycle policy.

### Proof of Concept
Conceptual (Move-level) reproduction, contingent on `abort_if_multisig_payload_mismatch_enabled()` being disabled:
1. Owner A creates a multisig transaction with `create_transaction(owner_A, multisig_addr, payload_benign)` — this stores `payload = Some(payload_benign)`, `payload_hash = None`.
2. Owners B, C (etc.) call `approve_transaction` reaching quorum, believing they are approving `payload_benign`.
3. Owner A (or any owner with execution rights) submits the actual on-chain transaction whose entry-function payload argument is `payload_malicious` instead of `payload_benign`.
4. In `validate_multisig_transaction`: `payload_hash.is_some()` is false (skips hash check); the stored-payload equality check is skipped because the feature flag is off.
5. `payload_malicious` executes with the multisig account's authority, despite never having reached quorum approval for its actual content. [10](#0-9)

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

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1323-1385)
```text
    #[lint::skip(unused_function)]
    /// Called by the VM as part of transaction prologue, which is invoked during mempool transaction validation and as
    /// the first step of transaction execution.
    ///
    /// Transaction payload is optional if it's already stored on chain for the transaction.
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

**File:** aptos-move/framework/move-stdlib/sources/configs/features.move (L1-24)
```text
/// Defines feature flags for Aptos. Those are used in Aptos specific implementations of features in
/// the Move stdlib, the Aptos stdlib, and the Aptos framework.
///
/// ============================================================================================
/// Feature Flag Definitions
///
/// Each feature flag should come with documentation which justifies the need of the flag.
/// Introduction of a new feature flag requires approval of framework owners. Be frugal when
/// introducing new feature flags, as too many can make it hard to understand the code.
///
/// Each feature flag should come with a specification of a lifetime:
///
/// - a *transient* feature flag is only needed until a related code rollout has happened. This
///   is typically associated with the introduction of new native Move functions, and is only used
///   from Move code. The owner of this feature is obliged to remove it once this can be done.
///
/// - a *permanent* feature flag is required to stay around forever. Typically, those flags guard
///   behavior in native code, and the behavior with or without the feature need to be preserved
///   for playback.
///
/// Note that removing a feature flag still requires the function which tests for the feature
/// (like `code_dependency_check_enabled` below) to stay around for compatibility reasons, as it
/// is a public function. However, once the feature flag is disabled, those functions can constantly
/// return true.
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
