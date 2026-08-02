## Finding

### Title
Stale multisig votes are not purged on owner removal, allowing resurrected approvals/rejections when an address is re-admitted as owner - ([File: aptos-move/framework/aptos-framework/sources/multisig_account.move])

### Summary
The reported bug class (revoked role membership retaining privileges because per-account state is not reset on removal) has a direct analog in Aptos's `multisig_account` module. When a multisig owner is removed, their vote (`transaction.votes`, a `SimpleMap<address, bool>`) on any still-pending `MultisigTransaction` is never cleared. If that same address is later re-added as an owner while the transaction is still pending, the stale, pre-removal vote is silently counted again during approval/rejection tallying at the transaction-admission boundary, without the owner casting a new vote.

### Finding Description
Votes are recorded per-transaction keyed by owner address in the `votes: SimpleMap<address, bool>` field of `MultisigTransaction`, set via `vote_transanction`: [1](#0-0) 

Tallying is done by `num_approvals_and_rejections_internal`, which iterates the account's *current* owners list and checks the vote map by address: [2](#0-1) 

Owner removal (`remove_owners` → `update_owner_schema`) only mutates the `owners` vector of `MultisigAccount`; it never touches `transactions[*].votes` for any pending transaction: [3](#0-2) 

The existing test suite only validates the "remove and stay removed" case — that a removed owner's vote is excluded from the tally because they're no longer in `owners`: [4](#0-3) 

It does not cover the "remove-then-re-add" case. Because votes are never purged, once the same address is re-added via `add_owner(s)` (which also only appends to `owners` without touching `votes`) [5](#0-4) , `num_approvals_and_rejections_internal` will again pick up the owner's old vote entry for any transaction that was created before the removal and is still pending (multisig transactions execute strictly in FIFO sequence order, so multiple transactions with higher sequence numbers can remain pending while an intervening owner-management transaction executes).

`validate_multisig_transaction`, which performs this tally, is explicitly documented as being invoked by the VM as part of transaction prologue/admission: [6](#0-5) 

This is functionally identical to the `AsSequentialSet` bug: an account's revocation does not reset the auxiliary state (`index` in the Solidity case, `votes` map entry here) tied to that account, so re-granting membership resurrects the old privilege/vote without a fresh authorization action.

### Impact Explanation
This breaks the "approval set must bind to the intended, current set of signers with fresh consent" invariant at the multisig admission boundary. A stale approval can be resurrected to help push a malicious pending transaction over the `num_signatures_required` threshold, or a stale rejection can be resurrected to block a legitimate transaction — in both cases without the re-admitted owner actually reviewing or voting on that specific pending payload. Since `validate_multisig_transaction` gates whether the multisig account's signer is granted to execute a transaction, this can lead to unauthorized execution under the multisig account's authority. Impact is High because it can affect execution of arbitrary payloads under a shared/institutional account.

### Likelihood Explanation
Likelihood is Medium: it requires (1) at least one pending multisig transaction that the target owner already voted on, (2) an owner-management transaction removing that owner while other transactions remain pending in the FIFO queue, and (3) a later transaction re-adding the same address. This is a plausible operational sequence for multisig accounts that rotate owners (e.g., temporarily removing and reinstating a signer, or an address changing custodial control between removal and re-addition), and does not require any privileged bug elsewhere — only ordinary owner-management entry functions (`remove_owner(s)`, `add_owner(s)`, `swap_owner(s)`), all of which are reachable by the multisig account's own governance flow.

### Recommendation
When an owner is removed in `update_owner_schema`, purge that owner's vote entry from every pending (unresolved) `MultisigTransaction` in `multisig_account_resource.transactions`, or alternatively require owners to re-vote by not counting any vote cast before the owner's most recent `(add)` timestamp/generation. A simpler and cheaper option is to track the "owner incarnation" (e.g. a monotonically increasing add/remove generation counter per multisig account) and only count votes cast during the owner's current membership tenure.

### Proof of Concept
1. Create a multisig account with owners `[O1, O2, O3]`, `num_signatures_required = 2`.
2. `O1` creates transaction #1 (payload P1); `O2` creates transaction #2 (payload P2, malicious). `O2` implicitly approves #2 upon creation, and additionally `O1` (before removal) approves #2 as well, giving `#2` 2 approvals (`O1`, `O2`) via `approve_transaction`.
3. A separate governance transaction (e.g. transaction #0, already resolved earlier) removes `O1` from owners — `remove_owners([O1])`. Per `update_owner_schema`, only `owners` is mutated; `transactions[2].votes[O1] = true` remains untouched.
4. At this point `can_be_executed(multisig, 2)` correctly excludes `O1`'s vote (matches existing test `test_validate_transaction_should_not_consider_removed_owners`), so #2 shows only 1 real approval (`O2`).
5. Before transaction #2 is resolved, another governance transaction re-adds `O1` — `add_owners([O1])`. `owners` becomes `[O2, O3, O1]` again; `votes` for transaction #2 is untouched and still contains `O1 -> true` from step 2.
6. Now `num_approvals_and_rejections_internal` for transaction #2 iterates current owners `[O2, O3, O1]`, finds `votes` entries for both `O2` and `O1`, and reports 2 approvals — meeting `num_signatures_required = 2` — even though `O1` never approved payload P2 after being re-admitted, and never had the chance to review it in its current, potentially malicious form.
7. `validate_multisig_transaction`/`can_be_executed` therefore authorizes execution of transaction #2 under the multisig account's signer at the VM prologue/admission stage, based on a resurrected, stale vote.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L986-1005)
```text
    /// Similar to add_owners, but only allow adding one owner.
    entry fun add_owner(multisig_account: &signer, new_owner: address) {
        add_owners(multisig_account, vector[new_owner]);
    }

    /// Add new owners to the multisig account. This can only be invoked by the multisig account itself, through the
    /// proposal flow.
    ///
    /// Note that this function is not public so it can only be invoked directly instead of via a module or script. This
    /// ensures that a multisig transaction cannot lead to another module obtaining the multisig signer and using it to
    /// maliciously alter the owners list.
    entry fun add_owners(
        multisig_account: &signer, new_owners: vector<address>) {
        update_owner_schema(
            address_of(multisig_account),
            new_owners,
            vector[],
            option::none()
        );
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
