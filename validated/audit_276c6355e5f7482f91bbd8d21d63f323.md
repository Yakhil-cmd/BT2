### Title
Missing Deadline Parameter in `switch_delegation_pool` Allows Staker to Front-Run Delegator into Higher Commission - (File: src/pool/pool.cairo)

### Summary
`switch_delegation_pool` in the `Pool` contract accepts no deadline or maximum-commission guard. A staker who has set a `commission_commitment` with a high `max_commission` can front-run a delegator's pending switch transaction by calling `set_commission` to raise their commission to `max_commission` immediately before the switch executes. The delegator is silently enrolled in the target pool at a commission rate they never agreed to, permanently reducing their yield share for every future epoch they remain in that pool.

### Finding Description
`Pool::switch_delegation_pool` (src/pool/pool.cairo lines 379–429) takes only `to_staker`, `to_pool`, and `amount`. It performs no check on the current commission of the target pool and accepts no caller-supplied deadline or `max_commission` bound. [1](#0-0) 

The function unconditionally calls `switch_staking_delegation_pool` on the staking contract, which credits the delegator to `to_pool` at whatever commission the staker currently charges. [2](#0-1) 

Commission is normally only allowed to decrease (`assert!(commission < old_commission)`), but when a staker has an **active** `commission_commitment`, `update_commission` permits any value up to `max_commission`: [3](#0-2) 

A staker can set `max_commission` up to `COMMISSION_DENOMINATOR` (10 000 = 100%) for a window of up to one year: [4](#0-3) 

### Impact Explanation
Once the delegator's `switch_delegation_pool` transaction lands, they are a member of the target pool and all future rewards are split at the staker's current (now elevated) commission. The delegator loses the difference between the commission they observed and the commission actually applied, for every epoch they remain in the pool. This constitutes ongoing theft of unclaimed yield from the delegator, with direct financial gain for the staker.

Impact: **High — Theft of unclaimed yield.**

### Likelihood Explanation
The precondition is that the target staker has an active `commission_commitment` with `max_commission` above the current commission. This is a publicly visible on-chain state. A rational staker wishing to attract delegators can advertise a low commission, set a commitment with a high `max_commission`, wait for delegators to submit switch transactions, and front-run those transactions by calling `set_commission` in the same block. Starknet's sequencer ordering makes this straightforward. The delegator has no on-chain recourse once the switch executes.

Likelihood: **Medium** (requires the staker to have a commitment active, but this is a deliberate, low-cost setup).

### Recommendation
Add a `max_commission: Commission` parameter to `switch_delegation_pool` (and symmetrically to `enter_delegation_pool`). Before completing the switch, assert that the target pool's current commission does not exceed the caller-supplied bound:

```rust
fn switch_delegation_pool(
    ref self: ContractState,
    to_staker: ContractAddress,
    to_pool: ContractAddress,
    amount: Amount,
    max_commission: Commission,   // <-- new
) -> Amount {
    // existing asserts ...
    let current_commission = get_commission_of(to_staker); // read from staking contract
    assert!(current_commission <= max_commission, "COMMISSION_EXCEEDS_MAX");
    // proceed with switch ...
}
```

Alternatively, add a `deadline: Timestamp` parameter and revert if `Time::now() > deadline`, mirroring the pattern already used by `unstake_action` and `exit_delegation_pool_action`.

### Proof of Concept

1. Staker S deploys a pool with commission = 5 % (500 / 10 000).
2. S calls `set_commission_commitment(max_commission: 9000, expiration_epoch: current + 52)` — publicly visible on-chain.
3. Delegator D, seeing commission = 5 %, calls `exit_delegation_pool_intent` on their current pool and then submits `switch_delegation_pool(to_staker: S, to_pool: pool_S, amount: X)`.
4. S observes D's pending transaction in the mempool and calls `set_commission(commission: 9000)` with higher gas priority. This is valid because the commitment is active: [5](#0-4) 

5. S's `set_commission` is sequenced first; commission is now 90 %.
6. D's `switch_delegation_pool` executes. No commission check exists: [6](#0-5) 

7. D is enrolled in pool_S at 90 % commission. Every epoch, 90 % of D's share of pool rewards flows to S instead of D. D has no way to exit immediately (exit requires another `exit_delegation_pool_intent` + wait window).

### Citations

**File:** src/pool/pool.cairo (L379-418)
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

            // Update pool_member_info and write to storage.
            pool_member_info.unpool_amount -= amount;
            if pool_member_info.unpool_amount.is_zero() {
                // unpool_amount is zero, clear unpool_time.
                pool_member_info.unpool_time = Option::None;
            }
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Serialize the switch pool data and invoke the staking contract to switch pool.
            let switch_pool_data = SwitchPoolData { pool_member, reward_address };
            let mut serialized_data = array![];
            switch_pool_data.serialize(ref output: serialized_data);
            self
                .staking_pool_dispatcher
                .read()
                .switch_staking_delegation_pool(
                    :to_staker,
                    :to_pool,
                    switched_amount: amount,
                    data: serialized_data.span(),
                    identifier: pool_member.into(),
                );
```

**File:** src/staking/staking.cairo (L748-777)
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
