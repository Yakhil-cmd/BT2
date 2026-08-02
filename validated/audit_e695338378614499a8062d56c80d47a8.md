### Title
Stale multisig owner votes are resurrected when a removed owner is re-added, allowing execution of a pending multisig transaction with the wrong approval set - (File: `aptos-move/framework/aptos-framework/sources/multisig_account.move`)

### Summary
`multisig_account.move` stores each owner's vote on a pending transaction in a per-transaction `SimpleMap<address, bool>` (`transaction.votes`) that is never cleared when an owner is removed from the account. Quorum counting (`num_approvals_and_rejections_internal`) simply intersects the *current* owner list with this persistent vote map. If an owner is removed and later re-added while the same transaction is still pending, their old vote is silently reinstated and counted toward quorum in `validate_multisig_transaction` — the function invoked at transaction admission (mempool validation and prologue) — without the re-added owner ever having voted on the transaction in their current capacity.

### Finding Description
Votes are recorded once, at transaction creation or on explicit `approve_transaction`/`reject_transaction` calls: [1](#0-0) 

Quorum is computed purely from the current owner list intersected with the (never-purged) votes map: [2](#0-1) 

Owner removal is performed by `update_owner_schema`, which only mutates the `owners` vector (via `vector::swap_remove`) and never touches any pending transaction's `votes` map: [3](#0-2) 

The existing regression test only proves the "removal" half of the invariant — that a removed owner's vote stops counting immediately after removal: [4](#0-3) 

It does not cover the case where the same address is subsequently re-added as an owner while the transaction is still unresolved. Because the vote entry for that address was never deleted, re-adding the owner (via `add_owner`/`add_owners`/`swap_owner`, all of which funnel through `update_owner_schema`) causes `num_approvals_and_rejections_internal` to immediately count that address's *old* vote again — approval or rejection — with no fresh signature or confirmation from the current key holder.

This directly affects the transaction-admission boundary: `validate_multisig_transaction` is explicitly the function invoked during mempool validation and prologue execution to decide whether the underlying transaction is authorized to execute: [5](#0-4) 

It uses the same tainted quorum counting (`can_execute` / `num_approvals_and_rejections`) to authorize execution.

### Impact Explanation
This breaks the core invariant of the multisig approval set: only current owners' genuine, current-context approvals should count toward the k-of-n quorum used to authorize execution. A stale, resurrected vote lets a transaction execute (or be wrongly rejected) using an approval that does not reflect the re-added owner's intent for that specific pending transaction — the exact "wrong approval set" class called out in the Admission Pivots. In the worst case (owner rotation used as a compromise-recovery mechanism — remove a suspected-compromised owner, then re-add the same address once the key is believed safe, or an address is swapped back in during owner-list churn), a previously cast approval on a still-pending malicious/stale transaction is silently reactivated and can push the transaction over quorum, causing unauthorized execution under the multisig account.

### Likelihood Explanation
No attacker privilege escalation is required beyond what owners can already normally do (create/approve/reject transactions, and modify owner set via `update_owner_schema`/`add_owner`/`remove_owner`/`swap_owner`), and multisig transactions can remain pending indefinitely (there is no forced expiry tied to owner-list changes). Any workflow that removes and later re-adds the same owner address (key rotation, temporary suspension and reinstatement, or an owner swap that returns the address later) while a transaction is still pending will trigger this deterministically — this is not a narrow race window but a straightforward, reproducible state-persistence bug.

### Recommendation
When owners are removed via `update_owner_schema` (and consequently `remove_owner(s)`, `swap_owner(s)`), also purge or invalidate that owner's vote entries from all currently pending transactions' `votes` maps (or, more generally, snapshot/require a fresh vote whenever the owner set changes). Alternatively, track a per-owner "epoch"/owner-set version at vote time and only count votes cast during the account's current owner-set epoch.

### Proof of Concept
1. Create a 2-of-3 multisig account with owners `{A, B, C}`.
2. `A` calls `create_transaction(A, multisig, PAYLOAD)` — this auto-registers `A`'s approval vote (`add_transaction`), so transaction #1 has 1/2 approvals.
3. Owners remove `A` via `remove_owner`/`update_owner_schema` (now owners = `{B, C}`); per existing behavior, transaction #1 no longer counts `A`'s vote and remains at 0 explicit approvals among `{B,C}`.
4. Sometime later (transaction #1 still pending, not executed or rejected), owners re-add `A` via `add_owner` (owners = `{A, B, C}` again). `A` never re-approves anything.
5. `num_approvals_and_rejections_internal` now iterates owners `{A,B,C}`, finds `A -> true` still present in `transaction.votes` from step 2, and counts it as an approval again — transaction #1 is back to 1/2 approvals purely from the stale entry, with no action by `A` in their current tenure.
6. If one more current owner (`B` or `C`) approves, `validate_multisig_transaction` will authorize execution using `A`'s stale, resurrected vote as one of the two required approvals. [6](#0-5)

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1321-1353)
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

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1586-1632)
```text
    /// Add new owners, remove owners to remove, update signatures required.
    fun update_owner_schema(
        multisig_address: address,
        new_owners: vector<address>,
        owners_to_remove: vector<address>,
        optional_new_num_signatures_required: Option<u64>,
    ) {
        assert_multisig_account_exists(multisig_address);
        let multisig_account_ref_mut =
            borrow_global_mut<MultisigAccount>(multisig_address);
        // Verify no overlap between new owners and owners to remove.
        new_owners.for_each_ref(|new_owner_ref| {
            assert!(
                !vector::contains(&owners_to_remove, new_owner_ref),
                error::invalid_argument(EOWNERS_TO_REMOVE_NEW_OWNERS_OVERLAP)
            )
        });
        // If new owners provided, try to add them and emit an event.
        if (new_owners.length() > 0) {
            multisig_account_ref_mut.owners.append(new_owners);
            validate_owners(
                &multisig_account_ref_mut.owners,
                multisig_address
            );
            emit(AddOwners { multisig_account: multisig_address, owners_added: new_owners });
        };
        // If owners to remove provided, try to remove them.
        if (owners_to_remove.length() > 0) {
            let owners_ref_mut = &mut multisig_account_ref_mut.owners;
            let owners_removed = vector[];
            owners_to_remove.for_each_ref(|owner_to_remove_ref| {
                let (found, index) =
                    vector::index_of(owners_ref_mut, owner_to_remove_ref);
                if (found) {
                    vector::push_back(
                        &mut owners_removed,
                        vector::swap_remove(owners_ref_mut, index)
                    );
                }
            });
            // Only emit event if owner(s) actually removed.
            if (owners_removed.length() > 0) {
                emit(
                    RemoveOwners { multisig_account: multisig_address, owners_removed }
                );
            }
        };
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L2268-2289)
```text
    #[test(owner_1 = @0x123, owner_2 = @0x124, owner_3 = @0x125)]
    fun test_validate_transaction_should_not_consider_removed_owners(
        owner_1: &signer, owner_2: &signer, owner_3: & signer) {
        setup();
        let owner_1_addr = address_of(owner_1);
        let owner_2_addr = address_of(owner_2);
        let owner_3_addr = address_of(owner_3);
        create_account(owner_1_addr);
        let multisig_account = get_next_multisig_account_address(owner_1_addr);
        create_with_owners(owner_1, vector[owner_2_addr, owner_3_addr], 2, vector[], vector[]);

        // Owner 1 and 2 approved but then owner 1 got removed.
        create_transaction(owner_1, multisig_account, PAYLOAD);
        approve_transaction(owner_2, multisig_account, 1);
        // Before owner 1 is removed, the transaction technically has sufficient approvals.
        assert!(can_be_executed(multisig_account, 1), 0);
        let multisig_signer = &create_signer(multisig_account);
        remove_owners(multisig_signer, vector[owner_1_addr]);
        // Now that owner 1 is removed, their approval should be invalidated and the transaction no longer
        // has enough approvals to be executed.
        assert!(!can_be_executed(multisig_account, 1), 1);
    }
```
