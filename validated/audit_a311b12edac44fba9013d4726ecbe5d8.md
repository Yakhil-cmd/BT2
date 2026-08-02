### Title
Multisig `num_signatures_required` threshold is read live (not cached per pending transaction), allowing approval-set manipulation to force execution or blocking of already-pending transactions - (File: `aptos-move/framework/aptos-framework/sources/multisig_account.move`)

### Summary
`multisig_account.move` stores a single global `num_signatures_required` field on `MultisigAccount` and reads it live via the `num_signatures_required()` view function every time a pending transaction's approval status is evaluated [1](#0-0) . This threshold is never captured/cached on the individual `MultisigTransaction` at creation time. Because the threshold itself can be changed by a separate multisig transaction (`update_signatures_required`, `add_owners_and_update_signatures_required`, `swap_owners_and_update_signatures_required`, etc.) while other transactions are still pending in the same queue, the effective approval requirement for an already-queued transaction can shift after it was created — exactly the "un-cached governance parameter" bug class from the external report.

### Finding Description
The VM-invoked prologue entry point `validate_multisig_transaction` (called during mempool validation and transaction execution) checks the number of approvals against the *current* on-chain `num_signatures_required`, not the value that existed when the transaction was queued: [2](#0-1) 

The same live-read pattern is used by the public view helpers `can_be_executed`, `can_execute`, `can_be_rejected`, and `can_reject`, all of which call `num_signatures_required(multisig_account)` directly against global storage instead of any per-transaction snapshot: [3](#0-2) 

Unlike `MultisigTransaction`'s payload/payload_hash, which are captured at creation time, the approval quorum requirement is not part of the `MultisigTransaction` struct at all — there is no field caching it. This means once a transaction is created and queued (with implicit approval from its creator), any subsequent multisig transaction that changes `num_signatures_required` (itself only requiring the then-current threshold to pass) immediately and retroactively changes the semantics of every other transaction sitting in the pending queue behind it.

### Impact Explanation
This mirrors both scenarios in the external report:
- **Lowering the bar retroactively**: Transaction A is created requiring 3-of-5 approvals and only accumulates 2 approvals (insufficient, would normally never execute). A colluding subset of owners then creates and passes Transaction B (`update_signatures_required` to 2-of-5, itself only needing 2 approvals if enough owners are removed/swapped, or reachable given quorum dynamics). Once B executes, Transaction A — which never received a third approval — can now be executed by any owner via `validate_multisig_transaction`/`can_execute`, since the check now compares against the new, lower `num_signatures_required`. This allows unauthorized execution of a multisig transaction under a lower approval bar than was in force when the transaction was authored and voted on, i.e., an authorization/approval-set bypass at the transaction admission boundary (VM prologue).
- **Raising the bar to block a transaction that already qualified**: Conversely, a transaction that already has enough approvals under the original threshold can be prevented from executing (DoS on legitimate transactions) if the threshold is raised before it is submitted for execution, since `can_be_executed`/`can_execute` re-evaluate the requirement live rather than honoring the quorum that was met at approval time.

Because `validate_multisig_transaction` is invoked directly by the VM as part of the prologue for `MultisigTransaction` payloads (i.e., at admission/execution boundary, not merely an off-chain view), this directly affects "which set of approvals is sufficient to execute a transaction under the multisig account's identity" — an approval-set validation defect at the authenticator/approval-admission layer as scoped by the task's admission pivots.

### Likelihood Explanation
Exploitability requires a coalition of owners who can (a) create/queue a transaction with fewer than the eventual required approvals, and (b) subsequently pass a separate `update_signatures_required`-style transaction that changes the threshold before the first transaction is executed or rejected. This is realistic in any multisig with owner churn or threshold-tuning governance, and does not require any signature forgery — it only requires ordinary multisig proposal/voting flows, exactly as described in the external report's scenarios. The main uncertainty is whether this is treated as expected behavior by design (multisig threshold changes are documented as taking effect immediately) versus an unintended admission-boundary bug; the code shows no mechanism (e.g., invalidating/re-validating pending transactions, or snapshotting the quorum at creation) to prevent the retroactive effect.

### Recommendation
Cache the effective `num_signatures_required` (and/or a snapshot of eligible owners) on each `MultisigTransaction` at creation time, and use that cached value in `can_be_executed`, `can_execute`, `can_be_rejected`, `can_reject`, and `validate_multisig_transaction`, rather than re-reading the live global value from `MultisigAccount`. Alternatively, invalidate/reset all pending transactions whenever `num_signatures_required` or the owner set changes, forcing them to be re-approved under the new rules.

### Proof of Concept
1. Owner set = {A, B, C, D, E}; `num_signatures_required = 3`.
2. A creates Transaction T1 (auto-approved by A ⇒ 1/3 approvals). B approves ⇒ 2/3. No third approval is obtained; T1 remains pending and not executable per [4](#0-3) .
3. A and B (with sufficient approvals under the *current* threshold of 3, e.g., recruiting C) create and pass Transaction T2 = `update_signatures_required(2)`, executed via `validate_multisig_transaction`, which succeeds because it only needs to satisfy the threshold in effect at T2's own execution time [2](#0-1) .
4. `MultisigAccount.num_signatures_required` is now 2.
5. Any owner calls `validate_multisig_transaction`/`can_execute` on T1. It now reads the live `num_signatures_required()` = 2, and T1's existing 2 approvals satisfy the check, so T1 executes even though it never received the 3 approvals required when it was created [5](#0-4) .

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L407-412)
```text
    #[view]
    /// Return the number of signatures required to execute or execute-reject a transaction in the provided
    /// multisig account.
    public fun num_signatures_required(multisig_account: address): u64 {
        borrow_global<MultisigAccount>(multisig_account).num_signatures_required
    }
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L471-524)
```text
    #[view]
    /// Return true if the transaction with given transaction id can be executed now.
    public fun can_be_executed(multisig_account: address, sequence_number: u64): bool {
        assert_valid_sequence_number(multisig_account, sequence_number);
        let (num_approvals, _) = num_approvals_and_rejections(multisig_account, sequence_number);

        sequence_number == last_resolved_sequence_number(multisig_account) + 1 &&
            num_approvals >= num_signatures_required(multisig_account) && can_execute_with_timelock(multisig_account, sequence_number, num_approvals)
    }

    #[view]
    /// Return true if the owner can execute the transaction with given transaction id now.
    public fun can_execute(owner: address, multisig_account: address, sequence_number: u64): bool {
        assert_valid_sequence_number(multisig_account, sequence_number);
        let (num_approvals, _) = num_approvals_and_rejections(multisig_account, sequence_number);
        if (!has_voted_for_approval(multisig_account, sequence_number, owner)) {
            num_approvals += 1;
        };

        is_owner(owner, multisig_account) &&
            sequence_number == last_resolved_sequence_number(multisig_account) + 1 &&
            num_approvals >= num_signatures_required(multisig_account) && can_execute_with_timelock(multisig_account, sequence_number, num_approvals)
    }

    /// Return true if the transaction with given transaction id can be executed immediately, or it has to wait
    /// for the timelock to expire.
    inline fun can_execute_with_timelock(multisig_account: address, sequence_number: u64, num_approvals: u64): bool {
        if (exists<MultisigAccountTimeLock>(multisig_account)) {
            let multisig_account_resource = &MultisigAccountTimeLock[multisig_account];
            let timelock = multisig_account_resource.timelock_period;
            let override_threshold = multisig_account_resource.override_threshold;

            // Get the pending transaction to check if the timelock has expired
            // Assume that the transaction has already been checked to exist and is valid
            let pending_transaction = get_transaction(multisig_account, sequence_number);

            // Use subtraction to avoid overflow (now_seconds() >= creation_time_secs is always true)
            let elapsed = now_seconds() - pending_transaction.creation_time_secs;

            // If the number of approvals meets the override threshold, or the timelock has expired, allow execution
            (override_threshold.is_some() && &num_approvals >= override_threshold.borrow()) || elapsed >= timelock
        } else {
            true
        }
    }

    #[view]
    /// Return true if the transaction with given transaction id can be officially rejected.
    public fun can_be_rejected(multisig_account: address, sequence_number: u64): bool {
        assert_valid_sequence_number(multisig_account, sequence_number);
        let (_, num_rejections) = num_approvals_and_rejections(multisig_account, sequence_number);
        sequence_number == last_resolved_sequence_number(multisig_account) + 1 &&
            num_rejections >= num_signatures_required(multisig_account)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1328-1359)
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
```
