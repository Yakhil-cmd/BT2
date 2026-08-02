### Title
Stale multisig votes are silently re-activated for pending transactions when a removed owner is re-added - (File: aptos-move/framework/aptos-framework/sources/multisig_account.move)

### Summary
`update_owner_schema()` removes an address from `MultisigAccount.owners` on owner removal, but it never touches the per-transaction `votes: SimpleMap<address, bool>` stored in any still-pending `MultisigTransaction` [1](#0-0) . Approval/rejection counting is computed by intersecting the *current* owners list with the transaction's `votes` map [2](#0-1) . This correctly invalidates a removed owner's vote while they are absent (confirmed by `test_validate_transaction_should_not_consider_removed_owners` [3](#0-2) ), but the stale entry is never deleted from `votes`. If that same address is later re-added as an owner while the original transaction is still pending (sequence number between `last_executed_sequence_number` and `next_sequence_number`), their old vote automatically counts again toward approval/rejection thresholds — without the owner ever re-casting a vote after being reinstated.

This mirrors the C4 LSP14 pattern exactly: a piece of "pending"/binding state (`_pendingOwner` there, `votes[owner]` here) is set once, is supposed to be invalidated by a state transition (owner renouncement / owner removal), but is only conditionally excluded (checked against current state) rather than being destroyed — so a later, seemingly unrelated action (accept ownership / re-adding the owner) silently reactivates the old, un-reviewed authorization.

### Finding Description
- Voting is recorded per address in `transaction.votes` via `vote_transanction()` [4](#0-3) .
- `num_approvals_and_rejections_internal()` determines approvals/rejections by iterating over the **current** `owners` vector and checking membership in `votes` [2](#0-1) .
- `update_owner_schema()` — used by `remove_owner(s)`, `swap_owner(s)`, and `add_owner(s)` — mutates only `MultisigAccount.owners` (and the timelock override threshold); it never iterates over pending `transactions` to purge votes belonging to a removed owner [5](#0-4) .
- Consequently, if owner `A` votes to approve pending transaction `T`, is then removed (so `T`'s live approval count drops, matching the intended "not considered" behavior), and is later re-added to `owners` before `T` is executed or rejected, `A`'s original stale vote automatically counts again the moment they reappear in `owners` — with zero on-chain re-authorization from `A` at that point in time.
- `execute_rejected_transaction`/VM-driven `successful_transaction_execution_cleanup` and `can_be_executed`/`can_be_rejected` all rely on this same approval/rejection counting function, so the reactivated stale vote directly affects whether `T` is admitted for execution.

### Impact Explanation
This breaks the "approval set must reflect the account's current, intended signer set" admission invariant required by the multisig approval mechanism (analogous to authenticator/approval-set binding failures called out in the Admission Pivots). An owner who was removed — e.g., because they went rogue, were suspected of key compromise, or simply changed their mind and would have rejected/abstained if asked again — can have their old, stale approval silently resurrected and counted toward execution of a transaction they were never asked to (re-)approve after being reinstated. This can push a transaction from "insufficient approvals" to "can_be_executed = true" without any of the currently-serving owners casting that vote, causing unauthorized transaction admission/execution under the multisig account.

### Likelihood Explanation
This requires: (1) a transaction to be created and partially approved, (2) the approving owner to be removed while the transaction is still pending, and (3) that same owner to be re-added before the transaction is executed or rejected. All three steps are achievable through normal, permitted multisig owner-management operations (`update_signatures_required`/`add_owner(s)`/`remove_owner(s)`, `swap_owner(s)`) with the same k-of-n threshold used for any other multisig action — no external/unprivileged actor is needed, but it does not require any special "governance/admin" privilege beyond what any owner-management transaction already has. The scenario can also arise unintentionally (e.g., an owner is swapped out and back in for unrelated reasons, e.g. key rotation via `swap_owner`), which increases realistic likelihood. Likelihood is Medium; exploitation is deterministic once the three-step precondition is met, and there is no additional signature check gating re-activation of the stale vote.

### Recommendation
When an owner is removed from `MultisigAccount.owners` in `update_owner_schema()`, iterate over all pending transactions (from `last_executed_sequence_number + 1` to `next_sequence_number - 1`) and delete the removed owner's entry from each transaction's `votes` map, so that if the same address is re-added later it must cast a fresh vote. Alternatively, track a "last owner-set version" or timestamp on both `MultisigAccount` and each vote entry, and only count a vote if it was cast while the voter was continuously an owner since the vote (i.e., invalidate votes cast in an owner "epoch" prior to a removal event for that specific address), rather than a stateless current-membership check that can be trivially re-satisfied.

### Proof of Concept
1. Create a multisig account with owners `[O1, O2, O3]`, `num_signatures_required = 2`.
2. `O1` calls `create_transaction(...)`, which auto-approves for `O1` (`add_transaction` adds `creator -> true` to `votes`) [6](#0-5) . Sequence number = 1.
3. `O2` calls `approve_transaction(O2, multisig, 1)`. Now `votes = {O1: true, O2: true}`, `can_be_executed(multisig, 1) == true` (2-of-3 threshold met with current owners `O1,O2,O3`).
4. Owners execute an `update_owner_schema`-based call (e.g. `remove_owners([O1])`) to remove `O1` — perhaps because `O1`'s key is suspected compromised. `owners = [O2, O3]`. Now `num_approvals_and_rejections_internal` only counts `O2`'s vote (since `O1 ∉ owners`), so `can_be_executed(multisig, 1) == false` (only 1 of 2 required approvals) — matching the framework's own test `test_validate_transaction_should_not_consider_removed_owners` [3](#0-2) .
5. Owners later execute `add_owners([O1])` (e.g., to restore `O1` after resolving the key concern, or as part of an unrelated owner swap). `owners = [O2, O3, O1]`. `update_owner_schema` never touched transaction #1's `votes` map, which still contains `O1: true` from step 2.
6. Immediately, without `O1` casting any new vote, `num_approvals_and_rejections_internal(owners, tx#1)` again counts both `O1` and `O2` as approvals (`votes` still has both keys and both `owners` contains them), so `can_be_executed(multisig, 1) == true` again — transaction #1 can now be executed based on `O1`'s stale, pre-removal vote, with no re-authorization from `O1` at the current point in time.

This confirms the local root cause: `update_owner_schema` (multisig_account.move:1586-1683) fails to purge per-owner vote state on removal, and `num_approvals_and_rejections_internal` (multisig_account.move:1532-1548) re-admits that stale state purely based on current-owner-list membership — the same "set once, cleared conditionally instead of destroyed, later silently reactivated" defect as the LSP14 `_pendingOwner` bug in the seed report.

### Citations

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

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1477-1486)
```text
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
