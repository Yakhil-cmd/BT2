### Title
Multisig payload substitution when `abort_if_multisig_payload_mismatch_enabled` is disabled - (File: `aptos-move/framework/aptos-framework/sources/multisig_account.move`)

### Summary
`validate_multisig_transaction`, the on-chain prologue check the VM runs before executing a Multisig transaction, only enforces that the caller-supplied `payload` matches the transaction that owners actually approved when either (a) only a hash was stored (`payload_hash.is_some()`), or (b) the full payload was stored **and** the feature flag `abort_if_multisig_payload_mismatch_enabled` is turned on. When a full payload was stored on-chain (`transaction.payload.is_some()`) but that feature flag is not enabled, the function performs no comparison at all between the stored, approved payload and the payload actually supplied for execution.

### Finding Description
`validate_multisig_transaction` in `aptos-move/framework/aptos-framework/sources/multisig_account.move` (lines 1328-1385) is invoked by the VM as part of transaction admission/prologue for `TransactionPayload::Multisig` transactions, receiving the `payload` bytes that the submitter wants to execute for the multisig proposal. [1](#0-0) 

The function's authorization logic is:
1. Confirm the sender is an owner and there are enough approvals for `sequence_number` — this establishes that the owners approved *some* transaction, identified by whatever was stored at creation time (`transaction.payload_hash` or `transaction.payload`).
2. If only a hash was stored, it checks `sha3_256(payload) == *payload_hash` — a strict binding between what owners approved and what is executed.
3. If the *full* payload was stored on-chain, the binding check `payload == *stored_payload` is only performed `if (features::abort_if_multisig_payload_mismatch_enabled() && transaction.payload.is_some() && !payload.is_empty())`.

If `abort_if_multisig_payload_mismatch_enabled` is disabled (its default/gated state on a given network), step 3 is skipped entirely. In that case, any owner holding the required approval count for `sequence_number` can supply an arbitrary `payload` — completely different from the payload the other owners approved and that is stored in `transaction.payload` — and it is passed straight through to execution with no on-chain verification that it matches what was voted on. This breaks the core multisig invariant that "each owner's approval is a vote for a specific, verifiable action" (the same class of defect as the reported bug: a required consistency check between the "should be enforced" value and the "actually enforced" value is missing/misconfigured, so subsequent execution proceeds on invalid input).

### Impact Explanation
This is a break of an approval-set binding invariant at the transaction-admission boundary: it allows a transaction that should fail admission (payload not matching the approved payload) to instead pass prologue and be executed and committed. A single authorized-but-malicious/compromised owner who has accumulated the numeric threshold of approvals for a queued sequence number (the approvals were cast for the originally-proposed `stored_payload`) can execute a different payload of their choosing (e.g., transferring funds, calling arbitrary entry functions authorized by the multisig account's signer) instead of the action the other owners actually approved. This is exactly the kind of "authorization to wrong action/wrong signer" outcome the admission gate is meant to prevent, and can result in unauthorized state transitions executed under the multisig account's authority.

### Likelihood Explanation
Exploitability depends entirely on the gating feature flag `abort_if_multisig_payload_mismatch_enabled` being disabled on the target network/instance. If the flag is off, the exploit requires no external permission beyond being one of the multisig account's owners with sufficient votes for a pending sequence number — a condition inherent to normal multisig operation. Because this is feature-gated, actual impact is contingent on the current on-chain feature state, which could not be verified in this review; if the feature is enabled by default in the currently deployed framework, the finding degrades to a defense-in-depth gap rather than an active vulnerability.

### Recommendation
Remove the feature-flag gate on the full-payload comparison, or make the comparison unconditional whenever `transaction.payload.is_some()` and `!payload.is_empty()`. At minimum, once `abort_if_multisig_payload_mismatch_enabled` is deemed safe, retire it fully rather than leaving an admission path where the payload/approval binding can be bypassed.

### Proof of Concept
1. Owner A creates a multisig transaction with `create_transaction` (stores full `payload_A` on-chain, `payload_hash` is `None`).
2. Owners B and C approve sequence number `N` for `payload_A`, reaching `num_signatures_required`.
3. On a network where `abort_if_multisig_payload_mismatch_enabled` is disabled, Owner A (who counts as an implicit approver per `has_voted_for_approval`) submits a `Multisig` transaction whose executable `payload` field is `payload_B` (an entirely different, self-serving call).
4. `validate_multisig_transaction` passes: approval count check succeeds (approvals were for `payload_A`, but this is never re-checked against the executed payload), `payload_hash.is_some()` is false so step 2's hash check is skipped, and the `abort_if_multisig_payload_mismatch_enabled` gate skips the stored-payload comparison.
5. `payload_B` executes with the multisig account's signer, despite never having been approved by owners B and C.

Note: I was unable to directly confirm the current default/rollout state of `abort_if_multisig_payload_mismatch_enabled` in this codebase snapshot (only its usage site was found via search); this should be verified in a running/current environment before treating this as an actively exploitable issue versus a latent gap protected by feature-flag defaults.

### Citations

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
