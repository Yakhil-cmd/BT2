## Finding: Stale multisig owner votes are not cleared on owner removal/re-addition, allowing pending transactions to be executed with a wrong approval set

### Title
Multisig owner votes are never purged from pending `MultisigTransaction.votes`, so re-adding a previously removed owner address silently reactivates their stale approval/rejection - ([File: aptos-move/framework/aptos-framework/sources/multisig_account.move])

### Summary
This is a direct structural analog of the Salty `_arbitrageProfits` bug: state tied to a prior membership/authorization context (`votes: SimpleMap<address, bool>` on a pending `MultisigTransaction`) is never cleared when the underlying authorization set changes (owner removal), and gets silently reused once that same address re-enters the authorized set (owner re-addition), producing an approval count that does not reflect the owner's actual current intent.

### Finding Description
Each pending `MultisigTransaction` stores a `votes: SimpleMap<address, bool>` keyed by owner address, set via `vote_transanction` (`approve_transaction`/`reject_transaction`) at [1](#0-0) .

The number of approvals/rejections used to decide `can_be_executed`/`can_be_rejected` is computed by iterating the **current** owners list and checking membership in the transaction's `votes` map: [2](#0-1) .

Owner removal/addition is done through `update_owner_schema`, which only mutates `multisig_account_ref_mut.owners` (append/swap_remove) - it never touches the `transactions` table or any `MultisigTransaction.votes` map: [3](#0-2) .

Because `num_approvals_and_rejections_internal` only checks "is this current owner's address present as a key in `votes`", the check is address-based, not tenure-based. If:
1. Owner `O` votes on pending transaction `T` (approve or reject) while a current owner,
2. `O` is removed via `remove_owners`/`swap_owners` (their vote correctly stops counting, as the existing test at [4](#0-3)  shows),
3. `T` is still pending (not yet executed/rejected — this can span an arbitrary amount of time since transactions execute strictly in order and a prior transaction may be pending),
4. `O` is later re-added as an owner (same address),

then `O`'s old, never-cleared vote entry in `votes` for `T` automatically counts again toward `T`'s approval/rejection tally, even though `O` never voted on `T` during their current tenure as owner and did not consent (or has changed their mind) under the current owner set/threshold. This is functionally identical to `_arbitrageProfits[poolID]` retaining stale contribution data across an unwhitelist/re-whitelist cycle and having it silently reused once the pool becomes whitelisted again.

### Impact Explanation
This breaks the "wrong approval set" invariant explicitly called out in the admission gate: transaction execution admission (`can_be_executed`) can be satisfied using an approval that does not correspond to the current authorized signer set's actual consent. In a k-of-n multisig, an attacker/insider scenario is straightforward: get removed and quickly re-added (e.g., legitimate owner rotation, or an owner who is removed for one round of governance and reinstated later), and any transaction that sat pending in the queue during that window silently regains that owner's old vote. This can push a transaction over the approval threshold and cause it to execute as the multisig account without that owner's current, informed approval — an unauthorized state transition under the wrong approval/signer set, directly matching the "Authenticator ... multisig ... approval validation accepting ... wrong approval set" admission pivot.

### Likelihood Explanation
This requires no external attacker capability beyond normal multisig operation: owner churn (temporary removal and later re-addition of the same address) is a supported, common operational pattern (`remove_owner`, `add_owner`, `swap_owner`), and multisig transactions can remain pending indefinitely because execution is strictly sequential by `sequence_number`, so a queue backlog easily creates the necessary window. No special privilege beyond the multisig's own normal governance flow (already-approved owner-management transactions) is needed to trigger the stale-vote reactivation — it's a bug in the module's bookkeeping, not a misuse of admin power.

### Recommendation
When removing owners in `update_owner_schema`, iterate all pending transactions in `multisig_account_ref_mut.transactions` and remove any vote entries keyed by the removed addresses (or maintain a "removed at sequence X" epoch per owner and only count votes cast at or after the owner's most recent (re-)addition). Alternatively, clear an owner's votes on all pending transactions at the moment they are removed, so re-adding them starts with a clean slate, mirroring the fix recommended for the Salty case (force settlement/clearing before allowing state to be reused across membership transitions).

### Proof of Concept
1. Create a 2-of-3 multisig with owners `[A, B, C]`.
2. `A` calls `create_transaction(A, multisig, PAYLOAD)` → transaction `seq=1` created, `votes = {A: true}` (creator auto-approves).
3. `B` calls `reject_transaction(B, multisig, 1)` → `votes = {A: true, B: false}`. `can_be_executed(1)` is false (1 approval, 1 rejection, need 2 approvals).
4. Governance removes `B`: `remove_owners(multisig_signer, [B])`. Owners are now `[A, C]`. `votes` map for tx 1 is untouched (`{A: true, B: false}` still stored).
5. Governance re-adds `B`: `add_owners(multisig_signer, [B])`. Owners are now `[A, C, B]`.
6. Without `B` calling `approve_transaction`/`reject_transaction` again, `num_approvals_and_rejections_internal` recomputes over current owners `[A, C, B]`: `A→true`, `B→false` (stale, reactivated), `C→` not voted. Net: 1 approval, 1 rejection — B's old rejection is silently reapplied despite B never re-voting after re-joining. Swap the roles (B's stale vote is `true`) and this becomes: B's old approval is silently reapplied to push a transaction to `can_be_executed() == true` without B's current consent. [2](#0-1) [5](#0-4) [4](#0-3)

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

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1586-1660)
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
        // If new signature count provided, try to update count.
        if (optional_new_num_signatures_required.is_some()) {
            let new_num_signatures_required =
                optional_new_num_signatures_required.extract();
            assert!(
                new_num_signatures_required > 0,
                error::invalid_argument(EINVALID_SIGNATURES_REQUIRED)
            );
            let old_num_signatures_required =
                multisig_account_ref_mut.num_signatures_required;
            // Only apply update and emit event if a change indicated.
            if (new_num_signatures_required != old_num_signatures_required) {
                multisig_account_ref_mut.num_signatures_required =
                    new_num_signatures_required;
                emit(
                    UpdateSignaturesRequired {
                        multisig_account: multisig_address,
                        old_num_signatures_required,
                        new_num_signatures_required,
                    }
                );
            }
        };
        // Verify number of owners.
        let num_owners = multisig_account_ref_mut.owners.length();
        assert!(
            num_owners >= multisig_account_ref_mut.num_signatures_required,
            error::invalid_state(ENOT_ENOUGH_OWNERS)
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L2281-2289)
```text
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
