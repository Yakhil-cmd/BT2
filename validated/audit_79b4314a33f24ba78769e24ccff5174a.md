### Title
Staker Can Instantly Increase Commission via Commitment to Extract Delegator Yield - (File: src/staking/staking.cairo)

---

### Summary

A staker can set a `CommissionCommitment` with a `max_commission` higher than the current commission, then instantly increase their commission to that ceiling right before reward distribution. This allows a staker to attract delegators with a low commission rate and then extract their yield by front-running reward distribution with a sudden commission spike — with no delay, no notice period, and no delegator recourse.

---

### Finding Description

**Root cause in `update_commission` (lines 1573–1609):**

When an active `CommissionCommitment` exists, the only constraints on a commission change are:

```rust
assert!(commission <= commission_commitment.max_commission, ...);
assert!(commission != old_commission, ...);
``` [1](#0-0) 

There is no requirement that commission can only decrease. With an active commitment, the staker can freely **increase** commission up to `max_commission`. The change is written to storage immediately with no delay:

```rust
staker_pool_info.commission.write(Option::Some(commission));
``` [2](#0-1) 

**Root cause in `set_commission_commitment` (lines 748–785):**

The only constraint on `max_commission` is that it must be `>= current_commission`:

```rust
assert!(current_commission <= max_commission, "{}", Error::MAX_COMMISSION_TOO_LOW);
``` [3](#0-2) 

This means a staker with commission = 1% can set `max_commission = 10000` (100%), creating a commitment that permits a full commission increase at any time during the commitment window (up to 1 year).

**The developers acknowledge this gap in a code comment:**

```
/// **Note**: Current commission increase safeguards still allow for sudden commission
/// changes.
``` [4](#0-3) 

**Commission is applied at reward distribution time.** The `_update_rewards` function uses the commission stored at the moment it is called: [5](#0-4) 

So a commission increase that takes effect one transaction before `update_rewards_from_attestation_contract` or `update_rewards` is called will apply to the entire epoch's rewards.

**Delegators have no analogous protection.** There is no parameter delegators can set to specify a maximum acceptable commission, and the exit window (minimum 1 week) makes it impossible to exit before a same-block commission increase affects reward distribution. [6](#0-5) 

---

### Impact Explanation

A staker can drain all delegator yield for any epoch by:

1. Operating at 1% commission to attract a large delegation pool.
2. Setting a commitment with `max_commission = 10000` (100%).
3. Calling `set_commission(10000)` in the same block as (or immediately before) attestation/`update_rewards`.
4. All epoch rewards flow to the staker as commission; delegators receive zero.

This is repeatable every epoch for the duration of the commitment (up to 1 year). The impact is **theft of unclaimed yield** from delegators.

---

### Likelihood Explanation

Medium-to-high. The attack requires only two setup transactions (`set_commission` to a low value, then `set_commission_commitment` with a high ceiling) and one execution transaction (`set_commission` to max, then attest). No special access, leaked keys, or external dependencies are needed. Any staker with a delegation pool can execute this. The economic incentive scales with pool size.

---

### Recommendation

Apply a delay to commission **increases** analogous to the existing exit wait window. Specifically:

- Commission increases should only take effect after at least `K` epochs (matching the consensus delay already used for other state changes like public key and token activation).
- Alternatively, emit a pending-increase event and enforce a minimum notice period before the new rate applies, giving delegators time to exit.

The current `CommissionCommitment` mechanism was intended to protect delegators by capping how high commission can go, but it inadvertently enables instant increases up to that cap with no notice.

---

### Proof of Concept

```
// Step 1: Staker sets low commission to attract delegators
staking.set_commission(100);  // 1%

// Step 2: Staker sets commitment with max = 100%
staking.set_commission_commitment(
    max_commission: 10000,
    expiration_epoch: current_epoch + 365
);

// Step 3: Delegators join the pool, expecting 1% commission
pool.enter_delegation_pool(amount: large_amount, ...);

// ... epochs pass, delegators accrue rewards ...

// Step 4: Staker increases commission to 100% right before reward distribution
staking.set_commission(10000);  // 100%

// Step 5: Staker attests — rewards distributed with 100% commission
attestation.attest(block_hash);
// → update_rewards_from_attestation_contract called
// → commission = 10000 is read from storage
// → all pool rewards flow to staker as commission
// → delegators receive 0 for this epoch
```

The attack is confirmed by the existing test `test_set_commission_with_commitment`, which demonstrates that `set_commission` successfully increases commission from `old_commission` to `old_commission + 2` when a commitment is active: [7](#0-6)

### Citations

**File:** src/staking/staking.cairo (L74-75)
```text
    pub(crate) const DEFAULT_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: WEEK };
    pub(crate) const MAX_EXIT_WAIT_WINDOW: TimeDelta = TimeDelta { seconds: 12 * WEEK };
```

**File:** src/staking/staking.cairo (L745-746)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
```

**File:** src/staking/staking.cairo (L769-770)
```text
            let current_commission = staker_pool_info.commission();
            assert!(current_commission <= max_commission, "{}", Error::MAX_COMMISSION_TOO_LOW);
```

**File:** src/staking/staking.cairo (L1583-1589)
```text
                if self.is_commission_commitment_active(:commission_commitment) {
                    assert!(
                        commission <= commission_commitment.max_commission,
                        "{}",
                        Error::INVALID_COMMISSION_WITH_COMMITMENT,
                    );
                    assert!(commission != old_commission, "{}", Error::INVALID_SAME_COMMISSION);
```

**File:** src/staking/staking.cairo (L1599-1601)
```text
            // Update commission in storage.
            staker_pool_info.commission.write(Option::Some(commission));

```

**File:** src/staking/staking.cairo (L2332-2346)
```text
            let (commission_rewards, total_pools_rewards, pools_rewards_data) = if staker_pool_info
                .has_pool() {
                self
                    .calculate_staker_pools_rewards(
                        :staker_address,
                        :staker_pool_info,
                        :strk_total_rewards,
                        :strk_total_stake,
                        :btc_total_rewards,
                        :btc_total_stake,
                        :curr_epoch,
                    )
            } else {
                (Zero::zero(), Zero::zero(), array![])
            };
```

**File:** src/staking/tests/test.cairo (L2088-2111)
```text
#[test]
fn test_set_commission_with_commitment() {
    let mut cfg: StakingInitConfig = Default::default();
    let staking_contract = deploy_staking_contract(:cfg);
    cfg.test_info.staking_contract = staking_contract;
    let staking_dispatcher = IStakingDispatcher { contract_address: staking_contract };
    stake_with_strk_pool_enabled(:cfg);

    // Set commitment.
    let staker_address = cfg.test_info.staker_address;
    let staker_info = staking_dispatcher.staker_info_v1(:staker_address);
    let max_commission = staker_info.get_pool_info().commission + 2;
    let expiration_epoch = staking_dispatcher.get_current_epoch() + 1;
    cheat_caller_address_once(contract_address: staking_contract, caller_address: staker_address);
    staking_dispatcher.set_commission_commitment(:max_commission, :expiration_epoch);

    // Update commission.
    let mut commission = max_commission;
    cheat_caller_address_once(contract_address: staking_contract, caller_address: staker_address);
    staking_dispatcher.set_commission(:commission);

    // Assert commission is updated.
    let staker_info = staking_dispatcher.staker_info_v1(:staker_address);
    assert!(staker_info.get_pool_info().commission == commission);
```
