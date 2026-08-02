Based on my analysis of the multisig account timelock feature, I found a genuine local admission-boundary flaw in the approval-counting logic that Deriverse's `get_reserve` overflow analog maps to here: **an off-by-one weakening of the approval set used to authorize bypassing a security control** (the timelock override threshold).

### Title
Multisig timelock `override_threshold` can be satisfied using the executing owner's unrecorded implicit vote, allowing timelock bypass with fewer real approvals than configured - (File: `aptos-move/framework/aptos-framework/sources/multisig_account.move`)

### Summary
`upsert_timelock_internal` lets owners configure an `override_threshold` that must be strictly greater than `num_signatures_required`, and is documented as the number of approvals needed to execute a multisig transaction *immediately*, bypassing the `timelock_period` delay. However, `validate_multisig_transaction`, the VM-invoked prologue/execution gate, always inflates the approval count by one implicit vote for the executing owner before checking this override threshold — regardless of whether that owner ever explicitly voted, and regardless of the `multisig_v2_enhancement_feature_enabled()` flag.

### Finding Description
`upsert_timelock_internal` enforces that `override_threshold` be strictly greater than `num_signatures_required`, framing it as a supermajority bar that must be met before the timelock delay can be skipped: [1](#0-0) 

`can_execute_with_timelock` allows immediate execution once `num_approvals` reaches `override_threshold`: [2](#0-1) 

The VM-facing entry point `validate_multisig_transaction` — called both during mempool/VM prologue and at execution — recomputes `num_approvals` and **unconditionally** adds an implicit approval for the executing owner if they haven't explicitly voted yet, then feeds that inflated value into `can_execute_with_timelock`: [3](#0-2) 

This "implicit vote on execute" convenience is appropriate for the base `num_signatures_required` quorum (an owner who executes is reasonably treated as also approving). But it is applied identically to the `override_threshold` check, whose entire purpose is to demand *more* explicit approvals than the base quorum before a time-delay safety control can be skipped. Because the implicit vote is added unconditionally in `validate_multisig_transaction` (not gated by `multisig_v2_enhancement_feature_enabled()`, unlike the initial `can_execute`/`can_be_executed` gate a few lines above), any owner who has *not* voted can call execute once exactly `override_threshold - 1` other owners have explicitly approved, and their own implicit vote will push the count to `override_threshold`, bypassing the timelock.

### Impact Explanation
The `override_threshold`/timelock mechanism is a deliberately configured, stronger authorization bar meant to gate immediate execution of sensitive multisig operations (e.g., large fund transfers, owner/threshold changes) that would otherwise be delayed for `timelock_period` (1 hour–14 days). This flaw silently reduces the real number of required distinct approvals by one in all cases, letting a coalition with one fewer genuine "yes" vote than configured execute immediately. For a multisig account depending on the override threshold as a supermajority safety valve, this is an unauthorized state transition (premature/unapproved execution) under the wrong approval set — directly matching the "approval validation accepting ... wrong approval set" admission pivot.

### Likelihood Explanation
This triggers under normal, unprivileged usage of a documented, user-facing feature (`upsert_timelock`/`create_with_owners_and_timelock`) with no special assumptions: any multisig account owner who has not yet voted can trigger it simply by calling the standard "execute multisig transaction" flow once the threshold-minus-one bar of explicit approvals is reached. No privileged or malicious node behavior is needed.

### Recommendation
When computing `num_approvals` for the `can_execute_with_timelock` override-threshold check inside `validate_multisig_transaction`, use the actual recorded vote count only when checking against `override_threshold` (do not add the implicit executor vote for that specific comparison), or require the executing owner to have already explicitly voted before their execution can count toward `override_threshold`. Alternatively, only apply the implicit-vote inflation to the base `num_signatures_required` comparison, keeping the override-threshold check strictly to recorded `simple_map` votes.

### Proof of Concept
1. Owner creates a multisig account with `num_signatures_required = 2`, 5 owners, and `upsert_timelock(timelock_period, override_threshold = Some(3))`.
2. Owner A creates a transaction (sequence_number = N).
3. Owners B and C explicitly call `vote_transaction(..., approved = true)` — 2 explicit approvals recorded (meets base quorum of 2, but not the override threshold of 3).
4. Owner D, who has never voted on this transaction, calls the execute entry function (invoking `validate_multisig_transaction`).
5. Inside `validate_multisig_transaction`, `num_approvals_and_rejections` returns 2; because D hasn't voted, `num_approvals` becomes 3, matching `override_threshold`.
6. `can_execute_with_timelock` returns `true` via the override branch, and the transaction executes immediately — even though only 2 owners ever explicitly approved it, one short of the configured 3-vote override supermajority meant to gate immediate execution.

### Citations

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L497-515)
```text
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
```

**File:** aptos-move/framework/aptos-framework/sources/multisig_account.move (L943-951)
```text
        let multisig_account_resource = &MultisigAccount[multisig_address];
        assert!(
            override_threshold.is_none() || *override_threshold.borrow() > multisig_account_resource.num_signatures_required,
            error::invalid_argument(EINVALID_TIMELOCK_OVERRIDE_THRESHOLD)
        );
        assert!(
            override_threshold.is_none() || *override_threshold.borrow() <= multisig_account_resource.owners.length(),
            error::invalid_argument(EINVALID_TIMELOCK_OVERRIDE_THRESHOLD)
        );
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
