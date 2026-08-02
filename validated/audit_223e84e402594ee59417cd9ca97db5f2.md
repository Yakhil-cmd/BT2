## Title
Multisig transaction execution can run a payload that does not match the on-chain stored/approved payload when `abort_if_multisig_payload_mismatch_enabled` is off - (File: `aptos-move/framework/aptos-framework/sources/multisig_account.move`)

### Summary
`multisig_account.move`'s `validate_multisig_transaction` verifies the caller-supplied `payload` argument against the on-chain `MultisigTransaction` in two different ways depending on how the transaction was originally created, and the stronger of the two checks is gated behind a feature flag that is off by default.

### Finding Description
When a multisig transaction is created via `create_transaction_with_hash`, only a `payload_hash` is stored on-chain; owners vote based on that hash and the full payload is supplied at execution time. `validate_multisig_transaction` checks this case unconditionally: [1](#0-0) 

But when a transaction is created via `create_transaction` (full payload stored on-chain, e.g. `transaction.payload = Some(payload)`), the executor is expected to pass the identical `payload` bytes at execution time, and the code only checks that this matches the stored payload **if a feature flag is enabled**: [2](#0-1) 

The gate is `features::abort_if_multisig_payload_mismatch_enabled()`. If that flag is disabled (its name and framing as an incremental/rollout flag strongly suggest it defaults to off / is a recent hardening addition), an owner who is authorized to execute the transaction (has enough approvals) can pass an arbitrary `payload` argument at execution time that differs from `transaction.payload` (the payload the other owners actually voted to approve), and the check is skipped entirely. The transaction is still popped off the queue as "executed" with `num_approvals` reflecting votes cast for the *original* payload, but whatever payload the executor actually submitted proceeds to execution (this is consistent with the general k-of-n multisig design where the caller-provided `payload` argument, not the stored one, is what actually gets executed by the VM's `execute_multisig_transaction` flow).

### Impact Explanation
This breaks the core admission invariant of a multisig account: that execution can only occur for a payload that has collected the required number of approvals from owners. If the payload-match check is skipped (flag disabled), a single authorized executor (who needs only enough approvals to be *able* to execute, and by design gets an implicit approval simply by calling execute) can substitute a completely different payload — e.g. transferring funds to an attacker-controlled address, adding a new owner, or rotating keys — while the on-chain event/approval record still shows the transaction that was actually voted on. This is a wrong-approval-set admission bypass: execution proceeds under the authorization of votes cast for one payload while a different, unapproved payload is what actually runs.

### Likelihood Explanation
Likelihood depends entirely on whether `abort_if_multisig_payload_mismatch_enabled` is active in production. If it is off (which its very existence as an opt-in flag implies it may be, e.g. during a phased rollout or on older/compatibility paths), the bypass requires no special privilege beyond being one of the owners entitled to call `execute` — a condition already satisfied by any legitimate transaction proposer/owner. I could not confirm from the available index whether this feature flag is enabled by default on mainnet/testnet or whether there is a compensating check on the API/VM side that forces `payload` to always equal the stored payload; that determination requires checking `aptos-move/framework/aptos-framework/sources/../move-stdlib/sources/configs/features.move` default value and the VM caller in `aptos_vm.rs`'s `execute_multisig_transaction`, which I was not able to fully inspect due to running out of tool iterations.

### Recommendation
Make the on-chain-payload match check unconditional (not gated behind `abort_if_multisig_payload_mismatch_enabled`) whenever `transaction.payload.is_some()`, mirroring the unconditional treatment already given to the `payload_hash` case. If the flag exists purely for a migration window, it should default to enabled for any deployed transaction validation logic before this code ships, and the plan to fully remove the gate should be tracked.

### Proof of Concept
Conceptual PoC (could not be executed against the live repo in this session):
1. Owner A calls `create_transaction(owner_a, multisig_account, PAYLOAD_LEGIT)` — stores `transaction.payload = Some(PAYLOAD_LEGIT)`.
2. Owner B calls `approve_transaction(owner_b, multisig_account, seq)` bringing approvals to the required threshold for `PAYLOAD_LEGIT`.
3. With `abort_if_multisig_payload_mismatch_enabled` disabled, Owner A (or any owner permitted to execute) submits a transaction whose executable calls into the VM's multisig execution path with `payload = PAYLOAD_MALICIOUS` instead of `PAYLOAD_LEGIT`.
4. `validate_multisig_transaction` checks quorum (`num_approvals >= num_signatures_required`) — passes, since approvals were recorded against the sequence number, not the payload bytes, for the `create_transaction` (non-hash) path — and skips the payload-match assert because the feature flag is off.
5. `PAYLOAD_MALICIOUS` executes with the multisig account's authority, despite never having been seen or approved by Owner B.

I was unable to confirm within this session (a) the default on/off state of `abort_if_multisig_payload_mismatch_enabled`, and (b) whether the VM caller (`execute_multisig_transaction` in `aptos-move/aptos-vm/src/aptos_vm.rs`) enforces payload identity through some other path (e.g. requiring the transaction's own `TransactionPayload::Multisig` structure to be the sole source of the executed payload, making the `payload` argument here purely advisory for the hash-only case). If the VM always derives `payload` strictly from the submitted `SignedTransaction`'s own multisig payload field and that in turn is required to equal `transaction.payload` by some other admission check, this finding would be moot — I recommend a Devin session with full repo/tool access to trace `execute_multisig_transaction`'s call site and the `MultisigTransactionPayload` construction end-to-end before treating this as confirmed exploitable.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1361-1371)
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
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1373-1385)
```text
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
