## Title
Multisig transaction executed with a payload that owners never approved when `abort_if_multisig_payload_mismatch_enabled` is disabled - (File: aptos-move/framework/aptos-framework/sources/multisig_account.move)

### Summary
`multisig_account::validate_multisig_transaction` is the prologue function invoked by the VM (both at mempool admission time and as the first execution step) to authorize execution of a proposed multisig transaction against the owners' recorded approvals.<cite repo="Jortegata/aptos-core--035" path="aptos-move/framework/aptos-framework/sources/multisig_account.move" start="1323="1329"/> For transactions created via `create_transaction` (full payload stored on-chain, `payload_hash = None`), the check that the payload supplied at execution time actually matches the payload the owners voted on is gated entirely behind the feature flag `abort_if_multisig_payload_mismatch_enabled`. [1](#0-0)  If that flag is disabled, an executing owner can supply any payload at execution time and it will be run with the multisig account's signer — despite the on-chain approvals having been cast for a completely different, stored payload.

### Finding Description
`validate_multisig_transaction` performs two independent payload-integrity checks depending on how the transaction was proposed:
1. If `payload_hash` is set (hash-only proposal), it always verifies `sha3_256(payload) == payload_hash`. [2](#0-1) 
2. If the full `payload` was stored on-chain instead (the common `create_transaction` path), the match between the stored payload and the payload actually supplied for execution is only checked `if (features::abort_if_multisig_payload_mismatch_enabled() && transaction.payload.is_some() && !payload.is_empty())`. [1](#0-0) 

This means the binding between "the payload the owners approved (their votes are recorded against `sequence_number`, not against payload bytes)" and "the payload that is actually dispatched to the VM for execution" is not an unconditional invariant — it depends on a feature flag. The quorum check (`num_approvals >= num_signatures_required`) only ever validates that enough owners voted `true` for the *transaction sequence number*; it never itself binds that vote to specific payload bytes. [3](#0-2)  The payload-matching assertion is the *only* mechanism that ties the approval to the approved payload content in the full-payload case, and it is optional.

This is a direct analog of the reported bug class: a state-cleanup/consistency step that should unconditionally accompany an admission-relevant action (here: binding executed calldata to what was actually voted on) is instead conditionally skipped, breaking the "approval set was for a specific payload" invariant and allowing a wrong-payload execution under an account/module context (the multisig signer) that the owners did not actually authorize for that payload.

### Impact Explanation
If `abort_if_multisig_payload_mismatch_enabled` is not enabled on a given network/version, any owner calling the execute entry point can substitute an arbitrary payload for a `create_transaction`-based proposal and have it executed with the multisig account's signer, as long as the sequence number has enough approval votes recorded. This is unauthorized transaction execution under the multisig account's authority with attacker-controlled call data — a state transition that should have failed pre-validation (payload mismatch) but instead commits. This is a high-impact "approval set does not bind to what executes" admission bypass matching the required impact gate ("Pre-validation mismatch that causes a transaction which should fail admission to execute and commit" and "multisig approval validation accepting the wrong approval set").

### Likelihood Explanation
Exploitability depends entirely on whether `abort_if_multisig_payload_mismatch_enabled` is active. I could not verify from the available index whether this feature flag is enabled by default on mainnet/testnet or is still in a rollout/gated state (the feature-flag definition lives in `aptos-move/framework/move-stdlib/sources/configs/features.move`, but I was not able to fetch its default-enablement code or the genesis feature list within this session). If the flag is disabled, the likelihood is high and requires no privileged access — only that the caller is one of the multisig's existing owners with rights to call the execute entry function, which is the expected caller for this contract. If the flag is enabled by default already, the exposure is limited to networks/deployments that have not yet turned it on.

### Recommendation
Make the full-payload match check unconditional (drop the `abort_if_multisig_payload_mismatch_enabled` feature gate) so that whenever `transaction.payload.is_some()`, the payload supplied at execution must always equal the stored payload, mirroring the unconditional behavior already used for hash-based proposals. If the flag exists purely for staged rollout/back-compat reasons, ensure it is fully enabled on all live networks before this code path is reachable, and add a defense-in-depth invariant test asserting `validate_multisig_transaction` cannot execute a payload that differs from what owners approved regardless of feature-flag state.

### Proof of Concept
1. Owner A creates a multisig account with owners `{A, B}`, `num_signatures_required = 2`.
2. Owner A calls `create_transaction(A, multisig_addr, payload_transfer_1_APT_to_A)` — full payload is stored on-chain (`payload_hash = None`). [4](#0-3) 
3. Owner B calls `approve_transaction(B, multisig_addr, seq)` — quorum of 2 is now reached for `seq`, but this vote is only recorded against `seq`, not against specific payload bytes. [5](#0-4) 
4. On a deployment where `abort_if_multisig_payload_mismatch_enabled` is disabled, Owner A calls the execute entry function supplying `payload_transfer_1000_APT_to_A` instead of the approved payload.
5. `validate_multisig_transaction` skips the payload-equality check (feature disabled) and only validates the quorum count for `seq`, which passes. [6](#0-5) 
6. The VM executes `payload_transfer_1000_APT_to_A` under the multisig account's signer — a transaction the quorum never actually approved.

Note: I was unable to confirm the current mainnet/testnet default state of the `abort_if_multisig_payload_mismatch_enabled` feature flag within the available index; this should be verified in a live session (e.g., via `aptos node get-feature-flags` or reading the genesis feature list) before treating this as an active, unguarded vulnerability versus an already-mitigated one.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1171-1183)
```text
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

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1210-1214)
```text
    /// Approve a multisig transaction.
    public entry fun approve_transaction(
        owner: &signer, multisig_account: address, sequence_number: u64) {
        vote_transanction(owner, multisig_account, sequence_number, true);
    }
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1348-1384)
```text
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
```
