## Finding: Multisig payload-mismatch check is feature-gated, allowing execution with an unapproved payload

### Title
Executing owner can substitute an unapproved transaction payload for a stored, already-approved multisig transaction when `abort_if_multisig_payload_mismatch_enabled` is off - (File: `aptos-move/framework/aptos-framework/sources/multisig_account.move`)

### Summary
`multisig_account::validate_multisig_transaction`, which is invoked by the VM prologue/execution path for `MultisigTransaction`, only checks that the caller-supplied `payload` matches the on-chain stored payload if the feature `abort_if_multisig_payload_mismatch_enabled` is turned on [1](#0-0) . When a transaction is created via `create_transaction` (the common, full-payload-on-chain path), `payload_hash` is `None` and only `payload` is stored [2](#0-1) . Since the hash-check branch is skipped when `payload_hash` is `None`, and the payload-equality check is skipped whenever the feature flag is disabled, an executing owner can supply an entirely different `payload` at execution time than the one the other owners actually approved.

### Finding Description
The intended k-of-n model is: owners vote on a specific stored payload, and once quorum is reached, any owner can execute it, with the VM verifying the caller-provided payload against what was actually approved <cite repo="Camomtat/aptos-core--011" path="aptos-move/framework/aptos-framework/sources/multisig_account.move" start="1-42" /> [3](#0-2) . That binding is enforced in two places:
- If the transaction was stored with only a hash (`create_transaction_with_hash`), the SHA3-256 of the supplied payload must equal the stored hash [4](#0-3) .
- If the full payload was stored on-chain (`create_transaction`), the supplied payload should equal the stored payload — but this check is gated behind `features::abort_if_multisig_payload_mismatch_enabled()` [1](#0-0) .

When the feature is disabled (or on any deployment/network where it has not been activated), a transaction created with `create_transaction` has `payload_hash = None` and the equality check is entirely skipped, so `validate_multisig_transaction` succeeds regardless of what `payload` the executor passes in. Because the multisig account acts as the signer for whatever payload is ultimately executed, this breaks the "approval validation accepting the wrong approval set" invariant: quorum approval was given for payload A, but the transaction that actually executes as the multisig account can be payload B, chosen unilaterally by whichever owner happens to execute the queued transaction.

### Impact Explanation
Any single owner capable of calling the execute-transaction entry point (a normal, otherwise-unprivileged capability shared by all owners, not requiring quorum by itself) can cause the multisig account to execute a payload that was never voted on by the other owners, as long as the account was created with a k-of-n multisig where the attacker holds one seat. This can be used to drain funds or invoke arbitrary approved-looking-but-different entry functions/scripts as the multisig account — analogous to the JOJO report's "call with attacker-controlled parameters that were never intended to be authorized." If `abort_if_multisig_payload_mismatch_enabled` is off, this is a full break of the multisig's core approval guarantee.

### Likelihood Explanation
Likelihood is contingent on the on-chain/network state of the `abort_if_multisig_payload_mismatch_enabled` feature flag. I was not able to confirm from the available index whether this flag is enabled by default on current mainnet/testnet genesis or in the release builder defaults; I found the flag defined in `move-stdlib/sources/configs/features.move` and referenced in `aptos-release-builder/src/components/feature_flags.rs`, but could not conclusively verify its enabled/disabled status. The existence of a purpose-built feature flag specifically to "abort if multisig payload mismatch" strongly suggests that, prior to this flag's introduction (and on any deployment where it remains off), this exact payload-substitution gap was live in production. If the flag is off on any active network, this is a live, unprivileged (within the owner set) exploit path.

### Recommendation
Make the payload-match check unconditional when `transaction.payload.is_some()`, rather than gating it behind a feature flag — a stored full payload should always be checked against the payload provided at execution time, with no way to bypass it. If backward compatibility for existing on-chain multisig transactions is a concern, gate the flag by a one-time migration/rollout rather than leaving normal execution silently unchecked.

### Proof of Concept
1. Owner A calls `create_transaction(owner_A, multisig, payload_transfer_to_charity)` — this stores `payload = Some(payload_transfer_to_charity)`, `payload_hash = None` [2](#0-1) .
2. Owners B, C vote to approve based on reviewing `payload_transfer_to_charity` (quorum reached).
3. On a network/deployment where `abort_if_multisig_payload_mismatch_enabled` is disabled, malicious Owner A submits the `MultisigTransaction` execution with a different `payload_drain_funds_to_attacker` argument.
4. `validate_multisig_transaction` skips the hash check (`payload_hash` is `None`) and skips the payload-equality check (feature disabled) [5](#0-4) , so validation passes.
5. The multisig account executes `payload_drain_funds_to_attacker` instead of the approved payload.

Note: I could not fully trace the exact plumbing in `aptos-move/aptos-vm/src/aptos_vm.rs` that feeds the caller-chosen `payload` bytes into the actual executed `MultisigTransactionPayload` (entry function/script) within the remaining tool budget, so the end-to-end "provided payload actually gets executed as-is" linkage should be independently confirmed by a Devin session with full repo/build access, along with the current on-chain/default status of the `abort_if_multisig_payload_mismatch_enabled` feature flag.

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

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1324-1333)
```text
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
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1361-1384)
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
```
