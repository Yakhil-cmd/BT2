## Title
Stale owner votes are not purged on removal and are silently reactivated if the same address is re-added as an owner, allowing pending multisig transactions to reach quorum without fresh approval - (File: `aptos-move/framework/aptos-framework/sources/multisig_account.move`)

### Summary
`multisig_account::update_owner_schema` mutates only the `owners` vector when owners are added or removed; it never touches the `votes` `SimpleMap` stored inside any pending `MultisigTransaction`. Approval/rejection state is keyed purely by address, and quorum counting (`num_approvals_and_rejections_internal`) only filters votes by checking membership in the *current* `owners` vector. This means a vote cast by an address is not permanently invalidated when that address is removed — it is merely temporarily excluded from the count. If the same address is later re-added as an owner while the original transaction is still pending, its old vote is counted again automatically, without the owner re-affirming approval under the current owner set/threshold.

### Finding Description
`vote_transanction` (`multisig_account.move:1225-1253`) stores an owner's approval/rejection directly in `transaction.votes: SimpleMap<address, bool>` for a given pending transaction, keyed by owner address: [1](#0-0) 

Quorum is computed by `num_approvals_and_rejections_internal`, which iterates the *current* `owners` vector of the multisig and checks whether that address has a vote recorded — it does not track when or under what owner-set state the vote was cast: [2](#0-1) 

`update_owner_schema`, which backs `add_owners`/`remove_owners`/`swap_owner` and similar entry points, only mutates the `owners` vector — it never removes stale entries from any pending transaction's `votes` map: [3](#0-2) 

The framework's own test `test_validate_transaction_should_not_consider_removed_owners` confirms that removal only *temporarily* excludes a vote from the count (because the removed address is no longer in `owners`), not that the vote is deleted: [4](#0-3) 

Because the vote entry itself is never deleted, if the same address is re-added to `owners` while the transaction (e.g. sequence number 1) is still pending, `num_approvals_and_rejections_internal` will again count that address's old vote — without the owner having re-approved the transaction under the current owner/threshold configuration. This is the direct analog of the external report's `VotesGCByVault` issue: state that should be invalidated on a trust-changing event ("removed owner"/"replaced governance") is instead retained and silently reactivated on a later trust-changing event ("re-added owner"/"reverted governance"), letting a stale approval satisfy admission (`validate_multisig_transaction`, called from the VM prologue during both mempool validation and execution) without a fresh, intentional vote.

### Impact Explanation
This allows a multisig transaction to be admitted/executed (via `validate_multisig_transaction`, invoked from mempool validation and the VM prologue) using an approval that was never actually given by the owner under the multisig's current membership/threshold. In practice, if an owner is removed for cause (e.g., suspected key compromise, exiting the organization) with a pending malicious/undesired transaction awaiting quorum, and that owner's address is subsequently re-added to the owner set (a plausible administrative action, e.g. reinstatement or an unrelated re-provisioning), the stale approval is silently restored and can push the pending transaction over quorum without any new signature or intent from that owner. This is a broken approval-set invariant at the multisig admission boundary, potentially causing unauthorized execution of a transaction that should require fresh consensus.

### Likelihood Explanation
Likelihood is Medium: it requires (1) a transaction that remains pending (not resolved) across an owner-removal and owner-re-addition cycle, and (2) the re-added address matching a prior voter. Multisig owner rotation for cause, followed by later re-provisioning of the same address, or rapid remove/re-add cycles (e.g., key rotation mistakes, security incident response, or malicious insiders orchestrating the sequence) are realistic operational scenarios, and no code path clears the stale vote in between.

### Recommendation
When an owner is removed in `update_owner_schema`, purge that owner's entries from `votes` in every pending `MultisigTransaction` (i.e., iterate `multisig_account_resource.transactions` and call `votes.remove(&owner)` for each removed owner), or alternatively require every remaining/re-added owner to re-vote by not counting any vote that predates the current owner-set "epoch" (e.g., track an owner-set version and invalidate/ignore votes recorded under an older version).

### Proof of Concept
1. Create multisig account with owners `{A, B, C}`, `num_signatures_required = 2`.
2. `A` creates transaction (sequence `1`); `A`'s creation auto-votes approve (`add_transaction`, `multisig_account.move:1477-1478`).
3. `B` calls `reject_transaction` (disagrees) — quorum not met.
4. Governance removes `A` via `remove_owners` (owners now `{B, C}`), intending the pending tx to require fresh consensus; confirmed not executable per existing test at `multisig_account.move:2268-2288`.
5. Later, `A` is re-added via `add_owners` (owners now `{A, B, C}` again) — no code path clears `A`'s original vote.
6. `can_be_executed`/`can_execute` on sequence `1` now again counts `A`'s original stale "approve" vote plus itself toward quorum, even though `A` never re-voted after being re-admitted, potentially reaching quorum (e.g., if `C` also approves) without `A`'s current, intentional consent.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1235-1243)
```text
        let transaction = multisig_account_resource.transactions.borrow_mut(sequence_number);
        let votes = &mut transaction.votes;
        let owner_addr = address_of(owner);

        if (votes.contains_key(&owner_addr)) {
            *votes.borrow_mut(&owner_addr) = approved;
        } else {
            votes.add(owner_addr, approved);
        };
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

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1612-1632)
```text
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

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L2268-2288)
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
```
