## Finding

### Title
Multisig transaction execution accepts a payload different from the one owners approved when `abort_if_multisig_payload_mismatch` is disabled - (File: aptos-move/framework/aptos-framework/sources/multisig_account.move)

### Summary
`validate_multisig_transaction`, which the VM invokes during mempool admission and as the first prologue step of multisig transaction execution, only verifies the caller-supplied `payload` against the transaction record in two conditional branches: (1) if `payload_hash` was stored (hash-only creation path), and (2) if the `abort_if_multisig_payload_mismatch_enabled` feature is enabled *and* a full `payload` was stored on-chain. When the full payload was stored on-chain (the common path via `create_transaction`) but the mismatch-abort feature is not enabled, neither check binds the executed payload to the one that owners voted on.

### Finding Description [1](#0-0) 

The quorum/timelock checks (`can_execute`/`can_be_executed`, `num_approvals_and_rejections`, `can_execute_with_timelock`) all operate purely on `sequence_number`/vote counts and never reference the `payload` argument passed into `validate_multisig_transaction`. Binding of the *approved content* to the *executed content* is done exclusively by the two `if` blocks at the bottom of the function:

- `if (transaction.payload_hash.is_some())` — only true for transactions created via the hash-only creation path.
- `if (features::abort_if_multisig_payload_mismatch_enabled() && transaction.payload.is_some() && !payload.is_empty())` — only enforced when this specific feature flag is turned on.

For the common case where a transaction is created with `create_transaction` (full payload stored on-chain, `transaction.payload_hash` is `None`), if `abort_if_multisig_payload_mismatch_enabled` is not active, **no comparison between the supplied `payload` and the stored, voted-on payload ever executes**. The owner who ultimately submits the execution transaction (who must merely satisfy quorum count, not necessarily be the only actor with knowledge of the true approved payload) can pass an arbitrary `payload` value, and the VM will proceed to execute it under the multisig account's signer as if it were the payload that reached quorum.

### Impact Explanation
This breaks the core multisig admission invariant: "the payload that is executed under the multisig account's signer authority must be the one that the required threshold of owners actually approved." If the mismatch-abort feature is not enabled, quorum is validated against sequence-number-indexed votes, but the *content* being executed is unconstrained — an executing owner can substitute a different action (e.g., different recipient/amount/module call) than what other owners approved, while the on-chain event/vote history still reflects approval of the original payload. This is a wrong-approval-set / broken-binding admission failure directly analogous to the read-only-reentrancy report's core lesson (a validated quantity — virtual price / approved payload — can be silently swapped for an unvalidated one at the point of use), causing unauthorized execution under the multisig account.

### Likelihood Explanation
Exploitability depends entirely on whether `abort_if_multisig_payload_mismatch_enabled` is active in a given deployment/genesis config. I was not able to confirm from the available index whether this flag defaults to enabled or disabled on current mainnet/testnet genesis (the search only surfaced the flag's declaration and gating sites, not its rollout status), so I cannot assert with certainty that this is currently exploitable in production. If the flag is disabled (e.g., not yet rolled out, or explicitly turned off on some network), the bug is trivially triggerable by any single owner with enough approvals to reach quorum, with no privileged assumptions beyond normal multisig ownership.

### Recommendation
Make the stored-payload comparison unconditional (independent of `abort_if_multisig_payload_mismatch_enabled`) whenever `transaction.payload.is_some()`, so that the executed payload is always checked against the payload that owners voted on. Reserve the feature flag only for controlling the *severity* of a mismatch (e.g., soft-fail vs hard-abort) rather than gating whether the check happens at all.

### Proof of Concept
1. Owner A creates a multisig transaction via `create_transaction(multisig_account, payload_X)`; `transaction.payload = Some(payload_X)`, `transaction.payload_hash = None`.
2. Owners B and C vote to approve, reaching quorum for `payload_X`.
3. On a network/config where `abort_if_multisig_payload_mismatch_enabled` is disabled, Owner A (or any owner satisfying quorum) submits the actual execution transaction with `payload = payload_Y` (e.g., transferring funds to an attacker-controlled address instead of the approved recipient).
4. `validate_multisig_transaction` passes: `payload_hash.is_some()` is false (skip check 1), and the feature-gated check 2 is skipped because the feature is off.
5. The VM proceeds to execute `payload_Y` under the multisig account's signer, despite only `payload_X` having reached quorum — unauthorized execution under the multisig account.

**Uncertainty flagged:** I could not verify from the indexed code whether `abort_if_multisig_payload_mismatch_enabled` is enabled by default in current genesis/feature configs. If it is unconditionally enabled today, the finding is a defense-in-depth/rollout-window issue rather than an immediately exploitable one; a Devin session with full repo/genesis config access would be needed to confirm the flag's current on-chain status.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1328-1385)
```text
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
