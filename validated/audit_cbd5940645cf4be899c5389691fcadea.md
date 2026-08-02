Note: `ABORT_IF_MULTISIG_PAYLOAD_MISMATCH` (feature id 70) is documented as "Lifetime: transient," implying it is intended to eventually be permanently enabled, but the code itself gates the actual payload-vs-approved-payload check behind this flag being on — I could not confirm from the index whether this flag is enabled by default on mainnet/testnet genesis, which is required to determine current exploitability.

### Title
Multisig transaction execution can run with a payload different from the one owners approved when `AbortIfMultisigPayloadMismatch` is disabled - (File: aptos-move/framework/aptos-framework/sources/multisig_account.move)

### Summary
`validate_multisig_transaction`, invoked by the VM prologue for `MultisigTransaction` execution, checks a submitted `payload` against the on-chain proposal only in two cases: (1) when the proposal was created with `create_transaction_with_hash` (only a `payload_hash` was stored), or (2) when the full payload was stored **and** the `abort_if_multisig_payload_mismatch_enabled` feature is turned on. When the full payload is stored on-chain (via `create_transaction`) and that feature flag is off, an executing owner can submit an arbitrary `payload` argument that is never checked against the approved `transaction.payload`, yet the transaction still executes as the multisig account using the attacker-supplied payload while consuming the votes cast for the original, different payload.

### Finding Description
`create_transaction` stores the approved payload on-chain and leaves `payload_hash` as `None`: [1](#0-0) 

At execution time, `validate_multisig_transaction` counts approvals for the stored `MultisigTransaction` (identified only by `sequence_number`, not by payload content), and then attempts to validate the *content* of the caller-supplied `payload` argument: [2](#0-1) 

Because `transaction.payload_hash.is_some()` is `false` in the full-payload case, the hash check is skipped entirely. The only remaining check comparing the submitted `payload` to the approved `transaction.payload` is wrapped in `features::abort_if_multisig_payload_mismatch_enabled()`. If that flag is disabled, `payload == *stored_payload` is never evaluated — the function returns successfully regardless of what `payload` bytes were submitted. The rest of the VM (`successful_transaction_execution_cleanup`) then executes using the attacker-controlled `transaction_payload` argument, not the approved one, per the multisig framework's execution flow described in the module.

This is structurally the same class of bug as the reported `Order` issue: a value that influences execution/outcome (`baseTokenData.toRecipient` / here, the executed entry-function payload) is decoupled from the data that was actually approved/"signed" (the owners' votes bind only to `sequence_number`, not to payload content, unless the extra flag is on).

### Impact Explanation
If exploitable (flag disabled), any single owner who is the "last" required approver — or even an owner acting alone if `num_signatures_required == 1` — can execute a completely different entry function/script than what other owners voted for. Since the multisig account is often used to control privileged operations (treasury, admin functions, contract upgrades), this allows unauthorized state transitions under the multisig account's signer authority without the actual approval of the other owners for that specific action — a direct sender/authorization-set confusion at the transaction-admission boundary (VM prologue `validate_multisig_transaction`).

### Likelihood Explanation
Exploitability is entirely gated on the on-chain state of the `AbortIfMultisigPayloadMismatch` feature flag (id 70). I was not able to confirm from the indexed code/config whether this flag is enabled by default in current mainnet/testnet genesis or in the release builder defaults, nor find a place that treats it as "cannot be disabled" (unlike several other flags in the same enum explicitly marked `// Enabled on mainnet, cannot be disabled`). Given the flag is still toggleable and not marked as permanently on, this remains a real conditional exploitation path rather than a confirmed live vulnerability — hence framed as a likely, but not certainly currently-live, condition. I'm flagging this uncertainty explicitly since the answer hinges on governance-controlled state I could not verify with the available tools.

### Recommendation
Make the payload-content check unconditional (remove the `abort_if_multisig_payload_mismatch_enabled()` gate) whenever a full payload is stored on-chain, so that execution can never proceed with a payload differing from the one that received owner votes, regardless of feature-flag state. Alternatively, bind approvals/votes to a hash of the payload content itself (rather than only `sequence_number`) so a mismatched payload can never reuse another payload's approvals.

### Proof of Concept
1. A 2-of-3 multisig account is created with owners A, B, C.
2. Owner A calls `create_transaction(multisig_account, payload_X)` — this stores `payload_X` on-chain and implicitly gives A's approval (`add_transaction`). [1](#0-0) 
3. Owner B calls `approve_transaction(multisig_account, sequence_number)`, having reviewed and approved `payload_X` (2 approvals reached, satisfying the 2-of-3 threshold).
4. On the `AbortIfMultisigPayloadMismatch` feature is disabled network state, Owner A (or B) submits a `MultisigTransaction` execution transaction with `transaction_payload = payload_Y` (a completely different, e.g. malicious, entry function call) instead of `payload_X`.
5. `validate_multisig_transaction` sees `transaction.payload_hash.is_none()` (skips hash check) and `abort_if_multisig_payload_mismatch_enabled() == false` (skips content check), so validation passes.
6. `payload_Y` executes as the multisig account despite only `payload_X` ever having received the required 2 approvals.

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
