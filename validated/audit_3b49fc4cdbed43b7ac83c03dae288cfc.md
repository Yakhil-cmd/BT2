### Title
Staker can front-run delegator's `enter_delegation_pool` / `switch_delegation_pool` to impose maximum commission - (File: src/pool/pool.cairo)

### Summary

The `enter_delegation_pool` and `switch_delegation_pool` functions in `src/pool/pool.cairo` accept no `max_commission` parameter. A staker holding an active `commission_commitment` can front-run either call by invoking `set_commission` to raise their commission up to `max_commission` (potentially 100%), causing the delegator to lose all yield during the mandatory exit wait window.

### Finding Description

**Root cause — missing slippage guard in delegation entry points:**

`enter_delegation_pool` and `switch_delegation_pool` in `src/pool/pool.cairo` do not validate the pool's current commission against any caller-supplied ceiling: [1](#0-0) [2](#0-1) 

The commission applied to all future rewards is read dynamically from the `Staking` contract at reward-distribution time via `get_commission_from_staking_contract`, so whatever commission the staker holds at that moment is what the delegator pays.

**Why commission can be increased — the `commission_commitment` escape hatch:**

Normally `set_commission` only allows decreases. However, when a staker has an *active* `commission_commitment`, `update_commission` permits any value up to `max_commission`, including values higher than the current commission: [3](#0-2) 

The codebase itself acknowledges this risk in a comment: [4](#0-3) 

`set_commission_commitment` allows `max_commission` up to `COMMISSION_DENOMINATOR` (10 000 = 100%): [5](#0-4) 

**Attack path:**

1. Staker calls `set_commission(200)` (2%) and then `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + N)`.
2. Delegator observes the 2% commission and submits `enter_delegation_pool(reward_address, amount)` or `switch_delegation_pool(to_staker, to_pool, amount)`.
3. Staker front-runs with `set_commission(10000)` (100%) — valid because the commitment is active and `10000 <= max_commission`.
4. Delegator's transaction executes; they are now in a 100%-commission pool.
5. Delegator must call `exit_delegation_pool_intent` and wait the full `exit_wait_window` (default 1 week, up to 12 weeks) before recovering funds.
6. All rewards accrued during that window are taken entirely by the staker.

### Impact Explanation

**High — Theft of unclaimed yield.**

During the mandatory exit wait window the delegator earns zero net rewards (100% commission). The staker captures all yield that would otherwise belong to the delegator. This is a direct, quantifiable loss of unclaimed rewards with no recourse for the delegator once the delegation is committed.

### Likelihood Explanation

**Medium.** The attack requires the staker to have previously set a `commission_commitment` with `max_commission` above the advertised commission. On Starknet, pending transactions are visible in the sequencer mempool, making front-running feasible. The staker has a clear financial incentive. The `commission_commitment` feature is a documented, intended mechanism, so stakers can legitimately set it up in advance.

### Recommendation

Add a `max_commission: Commission` parameter to both `enter_delegation_pool` and `switch_delegation_pool`. Before completing the delegation, assert that the pool's current commission does not exceed the caller-supplied ceiling:

```cairo
fn enter_delegation_pool(
    ref self: ContractState,
    reward_address: ContractAddress,
    amount: Amount,
    max_commission: Commission,   // <-- new
) {
    // ... existing checks ...
    let current_commission = self.get_commission_from_staking_contract();
    assert!(current_commission <= max_commission, Error::COMMISSION_EXCEEDS_MAX);
    // ... rest of logic ...
}
```

Apply the same guard to `switch_delegation_pool`. This mirrors the standard slippage-protection pattern and gives delegators a trustless guarantee about the commission they accept.

### Proof of Concept

```
// 1. Staker sets low commission and a commitment allowing up to 100%
staking.set_commission(200);                                    // 2%
staking.set_commission_commitment(max_commission: 10000,
                                  expiration_epoch: epoch + 52);

// 2. Delegator sees 2% and submits enter_delegation_pool
//    (transaction visible in mempool)

// 3. Staker front-runs — valid because commitment is active
staking.set_commission(10000);                                  // 100%

// 4. Delegator's tx executes — now in a 100%-commission pool
pool.enter_delegation_pool(reward_address, amount);

// 5. Delegator immediately exits but must wait exit_wait_window
pool.exit_delegation_pool_intent(amount);
// ... wait 1 week ...
pool.exit_delegation_pool_action(delegator);

// 6. All rewards earned during the wait window went to the staker.
//    Delegator's reward_address received 0 STRK.
```

### Citations

**File:** src/pool/pool.cairo (L182-199)
```text
        fn enter_delegation_pool(
            ref self: ContractState, reward_address: ContractAddress, amount: Amount,
        ) {
            // Asserts.
            self.assert_staker_is_active();
            let pool_member = get_caller_address();
            assert!(
                self.pool_member_info.read(pool_member).is_none(), "{}", Error::POOL_MEMBER_EXISTS,
            );
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let token_dispatcher = self.token_dispatcher.read();
            let token_address = token_dispatcher.contract_address;
            assert!(token_address != pool_member, "{}", Error::POOL_MEMBER_IS_TOKEN);
            assert!(token_address != reward_address, "{}", GenericError::REWARD_ADDRESS_IS_TOKEN);
            // Transfer funds from the delegator to the staking contract.
            let staker_address = self.staker_address.read();
            transfer_from_delegator(:pool_member, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);
```

**File:** src/pool/pool.cairo (L379-395)
```text
        fn switch_delegation_pool(
            ref self: ContractState,
            to_staker: ContractAddress,
            to_pool: ContractAddress,
            amount: Amount,
        ) -> Amount {
            // Asserts.
            assert!(amount.is_non_zero(), "{}", GenericError::AMOUNT_IS_ZERO);
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            assert!(
                pool_member_info.unpool_time.is_some(),
                "{}",
                GenericError::MISSING_UNDELEGATE_INTENT,
            );
            assert!(amount <= pool_member_info.unpool_amount, "{}", GenericError::AMOUNT_TOO_HIGH);
            let reward_address = pool_member_info.reward_address;
```

**File:** src/staking/staking.cairo (L745-747)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
        /// **Note**: Updating epoch info can impact the commission commitment expiration date.
```

**File:** src/staking/staking.cairo (L748-778)
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
