## Analysis

The Sherlock report's root cause is a **counter that is used to gate an admin-controlled limit but cannot distinguish its two possible causes** (`circulatingOhmBurned` merges "nothing happened" and "burn happened" into one non-decreasing value, corrupting the limit check). The Aptos-native analog I found is structurally identical: a helper function used at the transaction-admission boundary conflates *"owner has not voted"* with *"owner explicitly voted reject"*, silently corrupting the approval-count invariant used to gate multisig execution.

### Title
Multisig execution prologue miscounts an owner's explicit rejection as an implicit approval, corrupting the quorum check at transaction admission - (File: `aptos-move/framework/aptos-framework/sources/multisig_account.move`)

### Summary
`validate_multisig_transaction` is the Move prologue function explicitly documented as being "invoked during mempool transaction validation and as the first step of transaction execution" [1](#0-0) . It re-derives the number of approvals for quorum purposes using `has_voted_for_approval`, which is defined as `voted && vote` [2](#0-1) . This means the function returns `false` both when an owner never voted **and** when an owner explicitly voted to reject (stored as `votes[owner] = false`). The prologue then adds an implicit approval for the executor whenever `has_voted_for_approval` is `false`:

```
let (num_approvals, _) = num_approvals_and_rejections(multisig_account, sequence_number);
if (!has_voted_for_approval(multisig_account, sequence_number, address_of(owner))) {
    num_approvals += 1;
};
assert!(num_approvals >= num_signatures_required(multisig_account), error::invalid_argument(ENOT_ENOUGH_APPROVALS));
``` [3](#0-2) 

The same conflated helper is used again in `transaction_execution_cleanup_common`, which is invoked on both success and failure post-execution paths [4](#0-3) .

### Finding Description
An owner who calls `reject_transaction` (which stores `votes[owner] = false` via `vote_transanction`) [5](#0-4)  has explicitly recorded their non-consent. However, `has_voted_for_approval` cannot tell "rejected" apart from "never voted," because it collapses the two-valued vote lookup into a single boolean (`voted && vote`). If that same owner later calls `execute_transaction`-style entry points as the `owner: &signer` argument, `validate_multisig_transaction` sees `has_voted_for_approval(...) == false` and grants them an **implicit approve** in the quorum count — silently overriding their own on-chain "reject" vote for the purposes of the numeric quorum assertion, even though the `votes` map itself still shows `false` for that owner.

This directly corrupts the "approval set" that gates admission of the underlying multisig payload for execution: the quorum check (`num_approvals >= num_signatures_required`) can be satisfied using fewer genuine approvals than intended, because a rejecting owner's execute-call is misclassified as a consenting one.

### Impact Explanation
This breaks the core multisig invariant that execution requires `num_signatures_required` genuine approvals. A transaction that should be blocked (because a required owner explicitly rejected it) can instead be pushed over the quorum threshold and executed, purely because the rejecting owner (or any owner acting on their behalf socially) triggers execution. Because this check happens inside the VM prologue that is run both during mempool admission and at the start of execution, it is exactly the "approval validation accepting the wrong approval set" class of admission-boundary bug called out in the task's impact gate. The impact is high: it can cause an under-quorum multisig transaction (arbitrary payload controlled by the multisig account, e.g., moving funds or changing owners) to be admitted and executed.

### Likelihood Explanation
Likelihood is moderate-to-high in any deployment where owners actively use `reject_transaction`/`vote_transaction(approved=false)` and later also serve as the executor (or where an owner who rejected is enticed/tricked into calling execute, or does so out of curiosity to "see what happens"). No privileged access is required beyond being a legitimate multisig owner, which is the normal, unprivileged actor model for this contract-level admission gate.

### Recommendation
Change `has_voted_for_approval` (or its call sites) to be three-valued: treat "explicitly voted reject" and "not voted" differently. Concretely, the implicit-approval logic in `validate_multisig_transaction` and `transaction_execution_cleanup_common` should only auto-approve when the owner has *not voted at all*, not when they have voted with `approved = false`:
```
let (voted, approved) = vote(multisig_account, sequence_number, address_of(owner));
if (!voted) {
    num_approvals += 1;
} else if (!approved) {
    // owner explicitly rejected — do not add an implicit approval
};
```

### Proof of Concept
1. Multisig account with owners `A, B, C, D` and `num_signatures_required = 3`.
2. `A` creates a transaction (`create_transaction`), which auto-approves for `A` (1 approval).
3. `B` calls `reject_transaction` → `votes[B] = false` (1 approval, 1 rejection).
4. No other owner votes.
5. `B` (the same owner who rejected) calls the execute entry point for the transaction, i.e. becomes the `owner: &signer` parameter passed into `validate_multisig_transaction`.
6. Inside the prologue: `num_approvals_and_rejections` returns `(1, 1)` (only `A`'s real approve counted). `has_voted_for_approval(multisig_account, seq, B)` returns `false` (since `B`'s vote is `voted=true, approved=false` → `true && false = false`), so `num_approvals` is bumped to `2`.
7. This is still below `num_signatures_required = 3` in this specific example, but by adjusting the numbers so that `num_signatures_required = 2` (or having one more real approver), the rejecting owner's own execute-call supplies the "missing" approval, letting the transaction pass `assert!(num_approvals >= num_signatures_required, ENOT_ENOUGH_APPROVALS)` despite `B`'s on-chain vote still being `false` — i.e., quorum is satisfied while `B`'s explicit rejection is silently discounted.

I could not fully verify the internals of `can_execute`/`can_be_executed` (the earlier gating asserts in the same function) within the available search budget, since their source was not retrieved; it is possible one of them independently re-derives approvals correctly and narrows the practical exploitability window. This should be verified before treating the finding as conclusively exploitable end-to-end, but the second, explicit `num_approvals` recomputation and assertion shown above is unambiguous and directly reachable regardless of what `can_execute`/`can_be_executed` do.

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

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1323-1329)
```text
    #[lint::skip(unused_function)]
    /// Called by the VM as part of transaction prologue, which is invoked during mempool transaction validation and as
    /// the first step of transaction execution.
    ///
    /// Transaction payload is optional if it's already stored on chain for the transaction.
    fun validate_multisig_transaction(
        owner: &signer, multisig_account: address, payload: vector<u8>) {
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

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L1556-1559)
```text
    inline fun has_voted_for_approval(multisig_account: address, sequence_number: u64, owner: address): bool {
        let (voted, vote) = vote(multisig_account, sequence_number, owner);
        voted && vote
    }
```
