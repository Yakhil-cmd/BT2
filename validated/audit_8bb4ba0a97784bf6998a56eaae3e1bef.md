## Title
Multisig transaction payload/execution confusion when `abort_if_multisig_payload_mismatch_enabled` is disabled - (File: `aptos-move/framework/aptos-framework/sources/multisig_account.move`, `aptos-move/aptos-vm/src/aptos_vm.rs`)

### Summary
`validate_multisig_transaction` (the VM prologue for multisig transactions) only checks that the provided execution payload matches what was approved on-chain in two narrow cases: (1) when only a `payload_hash` was stored, or (2) when the feature `abort_if_multisig_payload_mismatch_enabled` is on AND the stored `transaction.payload` is `Some` AND the caller-supplied `payload` is non-empty. When the full `MultisigTransaction.payload` was stored on-chain (the common case for `create_transaction`) but the mismatch-checking feature is not enabled, or the executor simply supplies an empty payload, `validate_multisig_transaction` performs **no comparison at all** between the approved payload and what will actually be executed.

### Finding Description
Any owner can approve a multisig transaction with a specific `EntryFunction`/`Script` payload (visible to all owners, hashed/stored on chain). Execution, however, is driven by whatever `TransactionExecutableRef` the *executing* owner attaches to their own top-level transaction (`aptos-move/aptos-vm/src/aptos_vm.rs`, `execute_multisig_transaction`, lines ~1306-1348, and the mirrored prologue-time computation in `run_multisig_prologue`, `aptos-move/aptos-vm/src/transaction_validation.rs` lines 419-460). This `provided_payload`/`executable` is derived purely from the executor's own submitted transaction — it is not itself authenticated against the multisig owners' approvals.

The only backstop against a mismatched executable is the assertion inside `validate_multisig_transaction` (`aptos-move/framework/aptos-framework/sources/multisig_account.move` lines 1328-1385):
```
if (transaction.payload_hash.is_some()) {
    assert!(sha3_256(payload) == *payload_hash, ...);
};
if (features::abort_if_multisig_payload_mismatch_enabled()
    && transaction.payload.is_some()
    && !payload.is_empty()
) {
    assert!(payload == *stored_payload, ...);
}
```
`create_transaction` (the common entry point) stores the full payload (`transaction.payload = Some(...)`), not a hash (`transaction.payload_hash = None`). In that case the first `if` never fires. The second `if` is guarded by a feature flag *and* requires the executor-supplied `payload` to be non-empty. If the feature is disabled, or the executor supplies an empty executable (`TransactionExecutableRef::Empty`), the function falls through with zero payload-equality checks, while `get_next_transaction_payload` (lines 456-469 of the same file) silently substitutes the caller-provided (unchecked) payload whenever the stored `transaction.payload` is `None`, or otherwise returns the stored payload for actual execution.

This produces a pre-validation gap at the admission boundary: `validate_multisig_transaction` runs as the VM prologue (used both for mempool admission and execution, per its own doc comment "Called by the VM ... during mempool transaction validation and as the first step of transaction execution") and is supposed to guarantee that only a fully-approved payload can execute for the multisig account (i.e., binding execution to the owner-approved "signer set"/payload). Whenever the feature gate is off (which is the historical/legacy behavior — the flag was clearly added later as a fix for exactly this gap, based on the comment "verify that the provided payload matches the stored payload"), the admission check silently no-ops and the executor-controlled `executable` from `execute_multisig_transaction`/`run_multisig_prologue` becomes what is actually executed as the multisig account's signer, regardless of what was approved.

### Impact Explanation
This breaks the "approval validation accepting the wrong approval set" admission invariant: the multisig quorum's approval is supposed to bind to a specific payload, but the payload actually executed under the multisig account's authority can, depending on feature-flag state, diverge from what the quorum approved. Any owner (including one with insufficient standing approvals, since the transaction has already technically met the sequence/quorum gate for a *different* intended payload) executing the pending multisig sequence number can substitute an entirely different entry function/script to run with the multisig account as signer — an unauthorized state transition under the multisig account's signer authority.

### Likelihood Explanation
Exploitability is entirely dependent on the on-chain state of the `abort_if_multisig_payload_mismatch_enabled` feature flag (a governance-controlled feature). While the current mainnet/testnet state of this flag could not be verified from the repository alone, the feature's mere existence — introduced as a targeted mismatch check rather than baked directly and unconditionally into `validate_multisig_transaction` — indicates the flag is (or was) required to be explicitly enabled for the guarantee to hold, meaning any deployment/network that has not enabled it (or any legacy multisig account interacting with a fork/testnet that predates or gates this feature) has no on-chain enforcement that executed multisig payloads match approved ones.

### Recommendation
Make payload-match enforcement unconditional (not feature-gated) whenever `transaction.payload` is stored on-chain, regardless of whether the caller-supplied payload is empty; an empty caller-supplied payload should be rejected/treated as a mismatch rather than silently bypassing the check. Ensure `get_next_transaction_payload` and `validate_multisig_transaction` use a single, non-optional source of truth so execution can never diverge from what owners approved.

### Proof of Concept
Not independently reproducible without on-chain feature-flag state (whether `abort_if_multisig_payload_mismatch_enabled` is active on a given deployment); this could not be confirmed from the repository, so the finding is reported with that caveat rather than as a confirmed, currently-exploitable defect on any specific live network.