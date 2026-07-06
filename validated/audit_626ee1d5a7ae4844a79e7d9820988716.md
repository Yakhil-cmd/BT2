### Title
Maximum Commission Rate of 10000 (100%) Allows Staker to Steal All Delegator Yield - (File: src/staking/staking.cairo)

### Summary
The `COMMISSION_DENOMINATOR` constant is set to `10000`, meaning a staker can set their pool commission to `10000` (100%). Combined with the `set_commission_commitment` mechanism, a staker with existing delegators can raise their commission to 100% within a single epoch window, redirecting all delegator yield to themselves.

### Finding Description
In `src/staking/staking.cairo`, the constant `COMMISSION_DENOMINATOR` is defined as `10000`, representing 100% of delegator rewards. [1](#0-0) 

Both `set_commission` and `set_commission_commitment` enforce only that the value does not exceed this denominator: [2](#0-1) [3](#0-2) 

Normally, once commission is initialized, it can only be decreased. However, the `set_commission_commitment` mechanism explicitly allows a staker to raise commission up to `max_commission` within the commitment window. The `update_commission` internal function permits any value `<= commission_commitment.max_commission` when a commitment is active: [4](#0-3) 

Since `max_commission` is bounded only by `COMMISSION_DENOMINATOR` (10000), a staker can commit to `max_commission = 10000` and then immediately raise their commission to 100%, capturing all delegator rewards.

The spec itself acknowledges this design gap with a comment directly above `set_commission_commitment`: [5](#0-4) 

The reward split function confirms that at `commission = 10000`, `pool_rewards = 0` — delegators receive nothing: [6](#0-5) 

### Impact Explanation
**High — Theft of unclaimed yield from delegators.**

A staker who has attracted delegators with a low commission can use `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)` followed by `set_commission(10000)` within the same epoch window. All delegator rewards accrued from that point forward are redirected to the staker's reward address. Delegators who do not monitor on-chain events in real time lose 100% of their yield. The exit process (`undelegate_intent` + mandatory wait window) means delegators cannot immediately escape once the commission is raised.

### Likelihood Explanation
**Medium.** Any registered staker with an open delegation pool can execute this attack with two transactions. The only friction is the on-chain visibility of the `CommissionCommitmentSet` event, which gives delegators a window of at least one epoch to react. However, epoch durations may be short, delegators are not required to monitor events, and the exit wait window (`DEFAULT_EXIT_WAIT_WINDOW = 1 week`) means delegators cannot recover staked principal quickly even if they notice. The attack requires no privileged access, leaked keys, or external dependencies.

### Recommendation
Introduce a protocol-enforced maximum commission cap significantly below `COMMISSION_DENOMINATOR`. Based on the analog report's guidance (1000–3000), a reasonable cap would be `MAX_COMMISSION = 2000` (20%). This cap should be enforced in both `set_commission` (for initial setting) and `set_commission_commitment` (for `max_commission`):

```cairo
pub const MAX_COMMISSION: Commission = 2000; // 20%

// In set_commission:
assert!(commission <= MAX_COMMISSION, "{}", Error::COMMISSION_OUT_OF_RANGE);

// In set_commission_commitment:
assert!(max_commission <= MAX_COMMISSION, "{}", Error::COMMISSION_OUT_OF_RANGE);
```

### Proof of Concept
1. Staker calls `stake(...)` and `set_commission(500)` (5%), then `set_open_for_delegation(STRK_TOKEN_ADDRESS)`.
2. Delegators join the pool, attracted by the low commission.
3. Staker calls `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 1)`.
4. In the same epoch, staker calls `set_commission(10000)`.
   - `update_commission` check: `10000 <= 10000` ✓ (`INVALID_COMMISSION_WITH_COMMITMENT` not triggered)
   - `10000 != 500` ✓ (`INVALID_SAME_COMMISSION` not triggered)
   - Commission is written as `10000`.
5. From the next attestation onward, `split_rewards_with_commission(rewards, 10000)` returns `commission_rewards = rewards`, `pool_rewards = 0`.
6. All delegator yield flows to the staker's reward address. Delegators receive zero rewards until they exit, which requires surviving the mandatory `DEFAULT_EXIT_WAIT_WINDOW` (1 week). [7](#0-6) [8](#0-7)

### Citations

**File:** src/staking/staking.cairo (L73-73)
```text
    pub const COMMISSION_DENOMINATOR: Commission = 10000;
```

**File:** src/staking/staking.cairo (L728-728)
```text
            assert!(commission <= COMMISSION_DENOMINATOR, "{}", Error::COMMISSION_OUT_OF_RANGE);
```

**File:** src/staking/staking.cairo (L745-746)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
```

**File:** src/staking/staking.cairo (L752-752)
```text
            assert!(max_commission <= COMMISSION_DENOMINATOR, "{}", Error::COMMISSION_OUT_OF_RANGE);
```

**File:** src/staking/staking.cairo (L1580-1600)
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

            // Update commission in storage.
            staker_pool_info.commission.write(Option::Some(commission));
```

**File:** src/staking/utils.cairo (L68-75)
```text
pub(crate) fn split_rewards_with_commission(
    rewards_including_commission: Amount, commission: Commission,
) -> (Amount, Amount) {
    let commission_rewards = compute_commission_amount_rounded_down(
        :rewards_including_commission, :commission,
    );
    let pool_rewards = rewards_including_commission - commission_rewards;
    (commission_rewards, pool_rewards)
```

**File:** src/staking/utils.cairo (L81-89)
```text
pub(crate) fn compute_commission_amount_rounded_down(
    rewards_including_commission: Amount, commission: Commission,
) -> Amount {
    mul_wide_and_div(
        lhs: rewards_including_commission,
        rhs: commission.into(),
        div: COMMISSION_DENOMINATOR.into(),
    )
        .expect_with_err(err: InternalError::COMMISSION_ISNT_AMOUNT_TYPE)
```
