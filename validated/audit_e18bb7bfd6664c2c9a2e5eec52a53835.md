### Title
Rejected Multisig Vote Counted as Implicit Approval in `validate_multisig_transaction` Admission Check - ([File: aptos-move/framework/aptos-framework/sources/multisig_account.move])

### Summary
`validate_multisig_transaction` (and the `can_execute` view it relies on) is the on-chain admission gate the VM invokes during transaction prologue for multisig-account transactions. Its quorum-counting logic increments `num_approvals` whenever the executing owner "has not voted for approval," rather than checking whether the owner has voted at all. Because `has_voted_for_approval` returns `false` both when an owner never voted and when an owner explicitly voted to **reject**, an owner who has recorded an explicit rejection is silently counted as an implicit approval when they trigger execution, letting a transaction reach quorum and execute even though the real recorded approvals are insufficient.

### Finding Description
`validate_multisig_transaction` is documented as being "Called by the VM as part of transaction prologue, which is invoked during mempool transaction validation and as the first step of transaction execution" — i.e., it is a hard admission gate, analogous to the `ValidationLogic.sol` prologue check in the seed report. [1](#0-0) 

The quorum counting logic treats "not voted approval" the same as "voted approval":
```
let (num_approvals, _) = num_approvals_and_rejections(multisig_account, sequence_number);
if (!has_voted_for_approval(multisig_account, sequence_number, address_of(owner))) {
    num_approvals += 1;
};
assert!(num_approvals >= num_signatures_required(multisig_account), error::invalid_argument(ENOT_ENOUGH_APPROVALS));
``` [2](#0-1) 

`has_voted_for_approval` only returns `true` if the owner voted **and** the vote was `true` (approve):
```
inline fun has_voted_for_approval(multisig_account: address, sequence_number: u64, owner: address): bool {
    let (voted, vote) = vote(multisig_account, sequence_number, owner);
    voted && vote
}
``` [3](#0-2) 

Consequently, if an owner previously called `reject_transaction` (which records `votes[owner] = false` via `vote_transanction`), `has_voted_for_approval` returns `false` for that owner exactly as it would for an owner who never voted. When that same owner subsequently triggers execution (becomes the `owner` signer passed into the prologue), the code adds a phantom `+1` "implicit approval" for them, using their **explicit rejection** as if it were an unvoted, would-be approval. [4](#0-3) 

The identically flawed pattern also exists in the `can_execute` view function used by the same code path when `multisig_v2_enhancement_feature_enabled()`:
```
public fun can_execute(owner: address, multisig_account: address, sequence_number: u64): bool {
    ...
    if (!has_voted_for_approval(multisig_account, sequence_number, owner)) {
        num_approvals += 1;
    };
    is_owner(owner, multisig_account) && ... && num_approvals >= num_signatures_required(multisig_account) && ...
}
``` [5](#0-4) 

Notably, the *rejection* counterpart (`execute_rejected_transaction`) does not have this flaw — it explicitly casts a real rejection vote for the owner before counting, ensuring the on-chain vote state and the quorum count are always consistent:
```
if (!has_voted_for_rejection(multisig_account, sequence_number, owner_addr)) {
    reject_transaction(owner, multisig_account, sequence_number);
}
``` [6](#0-5) 

No equivalent explicit-vote-then-count fix exists on the approval/execute side, and the spec module documents this as a Critical invariant that is not actually enforced: [7](#0-6) 

### Impact Explanation
This breaks the multisig k-of-n admission invariant at the exact boundary the VM relies on for prologue validation of multisig transactions. An owner who has explicitly voted to reject a transaction can still cause it to pass admission and execute by acting as the executing signer, because their rejection is misused as a phantom approval. This can let a multisig transaction execute with fewer genuine approvals than `num_signatures_required`, i.e., unauthorized state transition under the multisig account's authority without the intended approval set — a high-severity break of the multisig authorization boundary.

### Likelihood Explanation
The path requires no special privilege beyond being one of the multisig's own owners, which is normal usage. Any owner can: (1) call `reject_transaction`, then (2) submit/trigger execution of the pending multisig transaction as the owner-signer. If the remaining owners' real approvals are one vote short of quorum, this rejecting owner's own execution call supplies the missing "approval" via the phantom-count bug — a straightforward, low-effort sequence achievable by a single dissenting owner.

### Recommendation
Change the implicit-vote logic to only add an implicit approval when the owner has **not voted at all**, not merely "not voted approval":
```
let (voted, vote) = vote(multisig_account, sequence_number, address_of(owner));
if (!voted) {
    num_approvals += 1;
} else {
    assert!(vote, error::invalid_argument(EOWNER_HAS_REJECTED_TRANSACTION));
};
```
Apply the same fix to `can_execute`/`can_be_executed` view functions and any other call sites that use `has_voted_for_approval` to derive an implicit approval count.

### Proof of Concept
1. Multisig account with 3 owners (A, B, C), `num_signatures_required = 3`.
2. Owner A creates transaction (implicit creator approval per `create_transaction`), giving 1 recorded approval.
3. Owner B calls `reject_transaction` → `votes[B] = false` (explicit rejection, 0 approvals, 1 rejection recorded).
4. No other owner approves — real approvals recorded = 1 (A only), which is `< 3`.
5. Owner B then submits the transaction that triggers `validate_multisig_transaction(owner=B, ...)` as part of the VM prologue for execution.
6. `has_voted_for_approval(multisig, seq, B)` returns `false` (B voted, but voted reject) → code executes `num_approvals += 1`, making `num_approvals = 2` (A's real approval + B's phantom "approval").
   - This is still short of 3 in this specific numeric example, but demonstrates the miscount mechanism precisely; with `num_signatures_required = 2` and only A's real approval recorded, B's phantom count alone reaches 2/2 and the assert at [8](#0-7)  passes, allowing execution despite B's explicit rejection and no genuine second approval.

**Uncertainty**: I could not fully trace whether an additional gate elsewhere (e.g., in the AptosVM prologue caller `run_multisig_prologue` in `aptos-move/aptos-vm/src/transaction_validation.rs`) independently re-validates real approval counts before allowing execution to proceed to the payload — from what was inspected, the VM simply forwards to `validate_multisig_transaction` and treats any non-abort as success. [9](#0-8)

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L483-493)
```text
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
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1210-1253)
```text
    /// Approve a multisig transaction.
    public entry fun approve_transaction(
        owner: &signer, multisig_account: address, sequence_number: u64) {
        vote_transanction(owner, multisig_account, sequence_number, true);
    }

    /// Reject a multisig transaction.
    public entry fun reject_transaction(
        owner: &signer, multisig_account: address, sequence_number: u64) {
        vote_transanction(owner, multisig_account, sequence_number, false);
    }

    /// Generic function that can be used to either approve or reject a multisig transaction
    /// Retained for backward compatibility: the function with the typographical error in its name
    /// will continue to be an accessible entry point.
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

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1283-1288)
```text
        if (features::multisig_v2_enhancement_feature_enabled()) {
            // Implicitly vote for rejection if the owner has not voted for rejection yet.
            if (!has_voted_for_rejection(multisig_account, sequence_number, owner_addr)) {
                reject_transaction(owner, multisig_account, sequence_number);
            }
        };
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1321-1333)
```text
    ////////////////////////// To be called by VM only ///////////////////////////////

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
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1348-1353)
```text
        // Count approvals, including the executing owner's implicit vote.
        let (num_approvals, _) = num_approvals_and_rejections(multisig_account, sequence_number);
        if (!has_voted_for_approval(multisig_account, sequence_number, address_of(owner))) {
            num_approvals += 1;
        };
        assert!(num_approvals >= num_signatures_required(multisig_account), error::invalid_argument(ENOT_ENOUGH_APPROVALS));
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1556-1559)
```text
    inline fun has_voted_for_approval(multisig_account: address, sequence_number: u64, owner: address): bool {
        let (voted, vote) = vote(multisig_account, sequence_number, owner);
        voted && vote
    }
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

**File:** aptos-move/aptos-vm/src/transaction_validation.rs (L462-479)
```rust
    session
        .execute_function_bypass_visibility(
            &MULTISIG_ACCOUNT_MODULE,
            VALIDATE_MULTISIG_TRANSACTION,
            vec![],
            serialize_values(&vec![
                MoveValue::Signer(txn_data.sender),
                MoveValue::Address(multisig_address),
                MoveValue::vector_u8(provided_payload),
            ]),
            &mut UnmeteredGasMeter,
            traversal_context,
            module_storage,
        )
        .map(|_return_vals| ())
        .map_err(expect_no_verification_errors)
        .or_else(|err| convert_prologue_error(err, log_context))
}
```
