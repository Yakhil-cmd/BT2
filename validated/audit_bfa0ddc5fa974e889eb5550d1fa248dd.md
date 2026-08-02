Confirmed the exact semantics: `vote()` at [1](#0-0)  returns `(voted, vote)` where `vote` is `voted && *votes.borrow(&owner)` — i.e., it is `false` both when the owner never voted AND when the owner explicitly voted "reject" (`false`). `has_voted_for_approval` is built directly on top of this and cannot distinguish "never voted" from "voted no": [2](#0-1) .

### Title
Rejecting owner's own execution attempt is silently converted into a phantom approval vote, allowing execution below the real approval threshold - (File: `aptos-move/framework/aptos-framework/sources/multisig_account.move`)

### Summary
`can_execute` and `validate_multisig_transaction` grant an implicit approval to whichever owner is currently trying to execute the transaction, based on the check `!has_voted_for_approval(owner)`. Because `has_voted_for_approval` returns `false` both for owners who never voted and for owners who explicitly voted **reject**, an owner who explicitly rejected a transaction can call the execution entry point and have their rejection silently reinterpreted as an implicit approval for the purpose of the threshold check, without ever changing their recorded vote.

### Finding Description
`can_execute` computes the real tally via `num_approvals_and_rejections`, which correctly counts an owner's explicit `false` vote as a rejection: [3](#0-2) . It then adds one more "implicit" approval for the calling owner if `!has_voted_for_approval(owner, ...)`: [4](#0-3) 

The intent (per the comment in `validate_multisig_transaction`, "Count approvals, including the executing owner's implicit vote") is to auto-approve an owner who hasn't voted yet and is now executing the transaction. But `has_voted_for_approval` is defined as `voted && vote` [2](#0-1) , so it is `false` for both "never voted" and "voted `false`/reject". Consequently `!has_voted_for_approval(owner)` is `true` in both cases, and the code cannot tell an owner who explicitly rejected apart from one who abstained — it grants the "hasn't voted yet, so approve implicitly" bonus even to an owner who intentionally voted "no."

This is exercised at the actual transaction-admission boundary: `validate_multisig_transaction` is invoked by the VM during prologue (mempool validation and execution) and gates whether a multisig-wrapped transaction is allowed to execute at all, via `assert!(can_execute(...), ENOT_ENOUGH_APPROVALS)`: [5](#0-4) . The same flawed pattern is duplicated in `can_reject`/`transaction_execution_cleanup_common` via `has_voted_for_rejection`, which has the symmetric flaw (an owner who explicitly approved gets an implicit "reject" bonus if they call `execute_rejected_transaction`) [6](#0-5)  and [7](#0-6) .

This is the direct Aptos-native analog of the fate-flip bug: the on-chain vote map correctly stores the owner's true intent (`false` = reject), but a separate boolean-derived "should this count toward the threshold" gate collapses two different states (never-voted vs. explicit-no) into one, letting the sender flip effective admission without a corresponding true state change — exactly the "going to zero looks the same as never having voted" confusion described in the seed report.

### Impact Explanation
This allows a transaction to be admitted and executed when the true owner votes do not meet `num_signatures_required`. For example, with `num_signatures_required = 2` and owners A, B: A creates the transaction (auto-approved, 1 real approval). B explicitly calls `reject_transaction` (recorded vote = `false`, real tally: 1 approval / 1 rejection). B then calls the multisig execution entry point themselves. `can_execute(B, ...)` computes real `num_approvals = 1`, sees `has_voted_for_approval(B) == false` (because B's vote is `false`, not because B never voted), and adds +1, yielding `num_approvals = 2 >= 2`, so the transaction is allowed to execute — despite B having explicitly rejected it and no owner other than the creator ever truly approving it. This is an unauthorized state transition/execution under a signer set that never actually satisfied the approval threshold, directly matching the "Unauthorized transaction execution... under the wrong signer set" admission-gate criterion.

### Likelihood Explanation
No special privilege is required — any owner who voted "no" can trigger this simply by later calling the execute entry point themselves, which is a normal, expected interaction pattern (owners routinely try to execute transactions they created or voted on). It requires only `num_signatures_required - real_approvals == 1`, a very plausible situation near a k-of-n threshold, and the multisig v2 enhancement feature (`multisig_v2_enhancement_feature_enabled`) that gates this code path, which is a standard/expected-enabled feature flag, not a privileged admin action.

### Recommendation
Distinguish "never voted" from "voted no" explicitly instead of relying on `has_voted_for_approval`/`has_voted_for_rejection` (both derived from the same collapsed boolean). Use the `voted` component returned by `vote()` directly: only grant the implicit approval bonus if `!voted` (the owner has no recorded vote at all), not merely `!has_voted_for_approval`. Apply the symmetric fix to `can_reject`/`transaction_execution_cleanup_common` for `has_voted_for_rejection`.

### Proof of Concept
1. Create a multisig account with owners `[A, B]` and `num_signatures_required = 2`, multisig v2 enhancement feature enabled.
2. `A` calls `create_transaction(...)` — this auto-adds vote `A -> true` [8](#0-7) . Real tally: 1 approval, 0 rejections.
3. `B` calls `reject_transaction(B, multisig_account, seq)` → `vote_transanction` records `B -> false` [9](#0-8) . Real tally: 1 approval, 1 rejection.
4. `B` submits the actual multisig transaction execution (payload matching the created transaction). VM prologue calls `validate_multisig_transaction(B, multisig_account, payload)`, which calls `can_execute(B, multisig_account, seq)`.
5. Inside `can_execute`: `num_approvals_and_rejections` returns `(1, 1)`. `has_voted_for_approval(B)` returns `false && ...` wait: `vote(B)` returns `(voted=true, vote=false)`, so `has_voted_for_approval = voted && vote = true && false = false`. So `!has_voted_for_approval(B) == true`, and `num_approvals` becomes `1 + 1 = 2 >= num_signatures_required (2)` → `can_execute` returns `true`.
6. The transaction is admitted and executed, even though the only real approval came from the creator and `B` explicitly rejected it.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L481-493)
```text
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
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L562-574)
```text
    public fun vote(
        multisig_account: address, sequence_number: u64, owner: address): (bool, bool) {
        let multisig_account_resource = borrow_global<MultisigAccount>(multisig_account);
        assert!(
            sequence_number > 0 && sequence_number < multisig_account_resource.next_sequence_number,
            error::invalid_argument(EINVALID_SEQUENCE_NUMBER),
        );
        let transaction = multisig_account_resource.transactions.borrow(sequence_number);
        let votes = &transaction.votes;
        let voted = votes.contains_key(&owner);
        let vote = voted && *votes.borrow(&owner);
        (voted, vote)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1225-1253)
```text
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

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1273-1296)
```text
    /// Remove the next transaction if it has sufficient owner rejections.
    public entry fun execute_rejected_transaction(
        owner: &signer,
        multisig_account: address,
    ) {
        assert_multisig_account_exists(multisig_account);
        assert_is_owner(owner, multisig_account);

        let sequence_number = last_resolved_sequence_number(multisig_account) + 1;
        let owner_addr = address_of(owner);
        if (features::multisig_v2_enhancement_feature_enabled()) {
            // Implicitly vote for rejection if the owner has not voted for rejection yet.
            if (!has_voted_for_rejection(multisig_account, sequence_number, owner_addr)) {
                reject_transaction(owner, multisig_account, sequence_number);
            }
        };

        let multisig_account_resource = borrow_global_mut<MultisigAccount>(multisig_account);
        let (_, num_rejections) = remove_executed_transaction(multisig_account_resource);
        assert!(
            num_rejections >= multisig_account_resource.num_signatures_required,
            error::invalid_state(ENOT_ENOUGH_REJECTIONS),
        );

```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1328-1346)
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
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1433-1453)
```text
    inline fun transaction_execution_cleanup_common(executor: address, multisig_account: address): u64 {
        let sequence_number = last_resolved_sequence_number(multisig_account) + 1;
        let implicit_approval = !has_voted_for_approval(multisig_account, sequence_number, executor);

        let multisig_account_resource = borrow_global_mut<MultisigAccount>(multisig_account);
        let (num_approvals, _) = remove_executed_transaction(multisig_account_resource);

        if (features::multisig_v2_enhancement_feature_enabled() && implicit_approval) {
            emit(
                Vote {
                    multisig_account,
                    owner: executor,
                    sequence_number,
                    approved: true,
                }
            );
            num_approvals += 1;
        };

        num_approvals
    }
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1463-1486)
```text
    inline fun add_transaction(
        creator: address,
        multisig_account: address,
        transaction: MultisigTransaction
    ) {
        if (features::multisig_v2_enhancement_feature_enabled()) {
            assert!(
                available_transaction_queue_capacity(multisig_account) > 0,
                error::invalid_state(EMAX_PENDING_TRANSACTIONS_EXCEEDED)
            );
        };

        let multisig_account_resource = borrow_global_mut<MultisigAccount>(multisig_account);

        // The transaction creator also automatically votes for the transaction.
        transaction.votes.add(creator, true);

        let sequence_number = multisig_account_resource.next_sequence_number;
        multisig_account_resource.next_sequence_number = sequence_number + 1;
        multisig_account_resource.transactions.add(sequence_number, transaction);
        emit(
            CreateTransaction { multisig_account: multisig_account, creator, sequence_number, transaction }
        );
    }
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1532-1548)
```text
    inline fun num_approvals_and_rejections_internal(owners: &vector<address>, transaction: &MultisigTransaction): (u64, u64) {
        let num_approvals = 0;
        let num_rejections = 0;

        let votes = &transaction.votes;
        owners.for_each_ref(|owner| {
            if (simple_map::contains_key(votes, owner)) {
                if (*simple_map::borrow(votes, owner)) {
                    num_approvals += 1;
                } else {
                    num_rejections += 1;
                };
            }
        });

        (num_approvals, num_rejections)
    }
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1556-1559)
```text
    inline fun has_voted_for_approval(multisig_account: address, sequence_number: u64, owner: address): bool {
        let (voted, vote) = vote(multisig_account, sequence_number, owner);
        voted && vote
    }
```
