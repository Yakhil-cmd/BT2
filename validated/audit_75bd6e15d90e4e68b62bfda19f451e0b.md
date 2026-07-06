### Title
Staker Can Instantly Raise Commission to 100% via Commitment, Stealing All Delegator Yield - (File: src/staking/staking.cairo)

### Summary
A staker can atomically call `set_commission_commitment` with `max_commission = 10000` (100%) and then immediately call `set_commission(10000)` in the same block. Because the commitment is active the moment it is written, the second call passes all guards and sets commission to 100%. Delegators receive zero yield from that point forward and cannot exit immediately — they must wait through the exit window (at least one week). All yield accrued during that window is diverted to the staker.

### Finding Description

`set_commission_commitment` in `src/staking/staking.cairo` writes a `CommissionCommitment` with a caller-supplied `max_commission` (bounded only by `COMMISSION_DENOMINATOR = 10000`) and a caller-supplied `expiration_epoch` (bounded only to be `> current_epoch` and `<= current_epoch + epochs_in_year`). [1](#0-0) 

The minimum valid `expiration_epoch` is `current_epoch + 1`. The commitment is immediately active after the write. There is no delay, no timelock, and no notification window enforced on-chain before the staker can act on it.

`set_commission` then calls `update_commission`, which — when a commitment is active — only checks:
1. `commission <= commitment.max_commission`
2. `commission != old_commission` [2](#0-1) 

There is no lower-bound check, no delay, and no minimum notice period. The code itself carries an explicit acknowledgment of this gap: [3](#0-2) 

**Attack sequence (two transactions, or one if batched):**

1. Staker calls `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)`.
2. Staker immediately calls `set_commission(commission: 10000)`.
3. Commission is now 100%. `split_rewards_with_commission` routes the entire reward amount to the staker; delegators receive 0.
4. Delegators must call `exit_delegation_pool_intent` and then wait through the exit window (`DEFAULT_EXIT_WAIT_WINDOW = 1 week`) before they can withdraw principal. [4](#0-3) 

During that week (or longer), every reward epoch distributes 100% of pool rewards to the staker.

### Impact Explanation

**High — Theft of unclaimed yield.**

All delegator yield accrued from the moment of the commission change until each delegator successfully exits is permanently redirected to the staker. Delegators cannot avoid this loss: the exit window is enforced on-chain and cannot be shortened by the delegator. The staker profits directly at delegators' expense.

### Likelihood Explanation

Any registered staker who has opened a delegation pool can execute this attack with two standard transactions. No privileged protocol role, no leaked key, and no external dependency is required. The staker is an unprivileged participant (from the protocol's perspective) who controls their own pool's commission parameter. The attack is cheap, repeatable, and leaves no on-chain recourse for delegators.

### Recommendation

Enforce a mandatory notice period between `set_commission_commitment` and the first `set_commission` call that raises commission. Concretely:

- Record the block timestamp (or epoch) when the commitment is set.
- In `update_commission`, reject any commission increase unless at least `N` epochs (e.g., `epochs_in_year / 12`, roughly one month) have elapsed since the commitment was written.
- Alternatively, cap `max_commission` increases per commitment to a small delta (e.g., 500 bps / 5%) so that reaching 100% requires many commitment cycles, each with a mandatory waiting period.

This mirrors the recommended mitigation in the reference report: bound the magnitude of a single fee change so that users have time to observe and exit before the change takes effect.

### Proof of Concept

```
// Epoch N, block B:
staking.set_commission_commitment(max_commission: 10000, expiration_epoch: N + 1);
// Commitment is immediately active.

// Epoch N, block B (same block or next):
staking.set_commission(commission: 10000);
// update_commission: commitment active → only checks commission <= 10000 ✓ and commission != old ✓
// Commission is now 10000 (100%).

// All subsequent reward distributions:
//   split_rewards_with_commission(total_rewards, commission=10000, denominator=10000)
//   → staker_rewards = total_rewards, pool_rewards = 0
// Delegators earn nothing.

// Delegators call exit_delegation_pool_intent() but must wait DEFAULT_EXIT_WAIT_WINDOW (1 week).
// All yield during that week is stolen by the staker.
``` [5](#0-4) [6](#0-5)

### Citations

**File:** src/staking/staking.cairo (L73-75)
```text
    pub const COMMISSION_DENOMINATOR: Commission = 10000;
    pub(crate) const DEFAULT_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: WEEK };
    pub(crate) const MAX_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: 12 * WEEK };
```

**File:** src/staking/staking.cairo (L725-743)
```text
        fn set_commission(ref self: ContractState, commission: Commission) {
            // Prerequisites and asserts.
            self.general_prerequisites();
            assert!(commission <= COMMISSION_DENOMINATOR, "{}", Error::COMMISSION_OUT_OF_RANGE);
            let staker_address = get_caller_address();
            let staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);

            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            if let Option::Some(old_commission) = staker_pool_info.commission.read() {
                self
                    .update_commission(
                        :staker_address, :staker_pool_info, :old_commission, :commission,
                    );
            } else {
                staker_pool_info.commission.write(Option::Some(commission));
                self.emit(Events::CommissionInitialized { staker_address, commission });
            }
        }
```

**File:** src/staking/staking.cairo (L745-747)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
        /// **Note**: Updating epoch info can impact the commission commitment expiration date.
```

**File:** src/staking/staking.cairo (L748-784)
```text
        fn set_commission_commitment(
            ref self: ContractState, max_commission: Commission, expiration_epoch: Epoch,
        ) {
            self.general_prerequisites();
            assert!(max_commission <= COMMISSION_DENOMINATOR, "{}", Error::COMMISSION_OUT_OF_RANGE);
            let staker_address = get_caller_address();
            let staker_info = self.internal_staker_info(:staker_address);
            assert!(staker_info.unstake_time.is_none(), "{}", Error::UNSTAKE_IN_PROGRESS);
            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            assert!(staker_pool_info.has_pool(), "{}", Error::MISSING_POOL_CONTRACT);
            let current_epoch = self.get_current_epoch();
            if let Option::Some(commission_commitment) = staker_pool_info
                .commission_commitment
                .read() {
                assert!(
                    !self.is_commission_commitment_active(:commission_commitment),
                    "{}",
                    Error::COMMISSION_COMMITMENT_EXISTS,
                );
            }
            // Staker must have a commission since it has a pool.
            let current_commission = staker_pool_info.commission();
            assert!(current_commission <= max_commission, "{}", Error::MAX_COMMISSION_TOO_LOW);
            assert!(expiration_epoch > current_epoch, "{}", Error::EXPIRATION_EPOCH_TOO_EARLY);
            assert!(
                expiration_epoch - current_epoch <= self.get_epoch_info().epochs_in_year(),
                "{}",
                Error::EXPIRATION_EPOCH_TOO_FAR,
            );
            let commission_commitment = CommissionCommitment { max_commission, expiration_epoch };
            staker_pool_info.commission_commitment.write(Option::Some(commission_commitment));
            self
                .emit(
                    Events::CommissionCommitmentSet {
                        staker_address, max_commission, expiration_epoch,
                    },
                );
```

**File:** src/staking/staking.cairo (L1580-1597)
```text
            if let Option::Some(commission_commitment) = staker_pool_info
                .commission_commitment
                .read() {
                if self.is_commission_commitment_active(:commission_commitment) {
                    assert!(
                        commission <= commission_commitment.max_commission,
                        "{}",
                        Error::INVALID_COMMISSION_WITH_COMMITMENT,
                    );
                    assert!(commission != old_commission, "{}", Error::INVALID_SAME_COMMISSION);
                } else {
                    assert!(
                        commission < old_commission, "{}", Error::COMMISSION_COMMITMENT_EXPIRED,
                    );
                }
            } else {
                assert!(commission < old_commission, "{}", Error::INVALID_COMMISSION);
            }
```
