### Title
Multisig transaction execution can run a payload that differs from the one owners approved when `abort_if_multisig_payload_mismatch_enabled` is disabled - (File: aptos-move/framework/aptos-framework/sources/multisig_account.move)

### Summary

### Finding Description
`multisig_account::validate_multisig_transaction` is the VM-invoked prologue that gates execution of a `MultisigTransaction`. When a transaction was created with the full payload stored on-chain (via `create_transaction`, which sets `payload = option::some(payload)` and `payload_hash = option::none()`), the executor supplies its own `payload: vector<u8>` argument at execution time. The function only cross-checks the supplied payload against the stored one when the `abort_if_multisig_payload_mismatch_enabled` feature is on: [1](#0-0) 

If that feature flag is disabled (or not yet enabled on a given network), the `if (transaction.payload_hash.is_some())` branch is skipped (since `payload_hash` is `None` for hash-less transactions), and the second `if (features::abort_if_multisig_payload_mismatch_enabled() && ...)` branch is also skipped, leaving no assertion that `payload == *stored_payload`. Owners voted/approved based on the stored payload shown by `create_transaction`, but the sender executing the transaction (any owner, per the module's own design comment "the owner who executes will pay for gas" and can supply an arbitrary payload) controls the actual `payload` bytes passed to `validate_multisig_transaction` and to the subsequent execution step.

### Impact Explanation
This breaks the "approval set binds to the intended payload" invariant central to the multisig admission model: the quorum of owner approvals is supposed to authorize a specific, previously-disclosed transaction payload, not an arbitrary substitute chosen unilaterally by whichever owner triggers execution. If the payload-match feature gate is off, a single owner (who already has authority to submit *some* transaction) could execute a different entry function/payload than what other owners reviewed and voted for, effectively forging the approval set for a payload nobody else agreed to. This is exactly the "approval validation accepting the wrong approval set" class described in the admission gate.

### Likelihood Explanation
Exploitability is entirely gated by whether `abort_if_multisig_payload_mismatch_enabled` is turned on for the network/version in question; I could not verify from the indexed code whether this feature is enabled by default on mainnet or is still guarded as an in-progress rollout flag. If it is off (e.g., during a migration window, on a devnet, or on any deployment that hasn't activated it), the bypass is real and requires no special privilege beyond being an existing owner who can call the multisig execution entry point. I was not able to trace, within the available index, the exact point in `aptos-move/aptos-vm/src/aptos_vm.rs` where the `payload` argument passed to `validate_multisig_transaction` is chosen for actual execution (i.e., whether execution always uses the *stored* payload regardless of the check, which would neutralize this) versus using the executor-supplied `payload`. That trace is necessary to confirm whether the missing check is merely a redundant-validation gap or an actual execution-payload substitution vulnerability.

### Recommendation
Make the payload-match assertion for on-chain-stored payloads unconditional (not gated behind `abort_if_multisig_payload_mismatch_enabled`), or, if the feature flag is meant only to control soft rollout of a new codepath, ensure the actual bytes used for execution when `transaction.payload.is_some()` are always the on-chain stored payload rather than the caller-supplied argument. Confirm in the VM adapter (`aptos-move/aptos-vm/src/aptos_vm.rs`) which payload variable actually reaches the executed entry function, and add a regression test asserting that execution reverts if `payload != stored_payload` regardless of feature-flag state.

### Proof of Concept
1. Owner A calls `multisig_account::create_transaction(owner_A, multisig_addr, payload_X)` — full `payload_X` stored on-chain, `payload_hash = None`.
2. Owners B, C review `payload_X` off-chain (e.g., via API) and call `approve_transaction` to reach quorum.
3. On a deployment where `abort_if_multisig_payload_mismatch_enabled` is disabled, owner A (or any owner with an implicit/explicit approval) submits a `MultisigTransaction` execution with a *different* `payload_Y` in the transaction's execution payload field.
4. `validate_multisig_transaction` runs: `transaction.payload_hash.is_some()` is `false` (skip first check); `features::abort_if_multisig_payload_mismatch_enabled()` is `false` (skip second check) — no assertion fails.
5. If the VM subsequently executes using the supplied `payload_Y` rather than the stored `payload_X`, the multisig account executes an operation the other owners never approved.

**Caveat:** Step 5 is unverified against the exact `aptos-vm` execution path in this index; confirming it is required before treating this as a proven, currently-exploitable bug rather than a defense-in-depth gap.

### Citations

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
