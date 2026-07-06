### Title
Staker Can Increase Commission During Exit Window to Reduce Delegator Yield When Switching Pools — (File: `src/pool/pool.cairo`)

### Summary
`switch_delegation_pool` accepts no `max_commission` parameter. A staker with an active commission commitment can raise their commission between a delegator's `exit_delegation_pool_intent` call and their subsequent `switch_delegation_pool` call, causing the delegator to enter the destination pool at a higher commission rate than they observed and intended to accept.

### Finding Description

The delegation-switch flow is a two-step process:

1. Delegator calls `exit_delegation_pool_intent` on their current pool, which starts the exit window.
2. After the window, the delegator calls `switch_delegation_pool(to_staker, to_pool, amount)`.

Between these two steps, the staker controlling `to_pool` can freely change their commission. The `set_commission` function in `Staking.cairo` normally only allows commission to be **decreased**: [1](#0-0) 

However, when an active `CommissionCommitment` exists, the staker may set commission to **any value up to `max_commission`**, which can be higher than the current commission: [2](#0-1) 

A staker can create a commitment at any time (as long as no active one exists), with `max_commission` up to `COMMISSION_DENOMINATOR` (10000 = 100%): [3](#0-2) 

The `switch_delegation_pool` function in `Pool.cairo` performs no check on the destination pool's commission and accepts no `max_commission` guard parameter: [4](#0-3) 

**Attack sequence:**

1. Staker deploys a pool with commission 5% to attract delegators.
2. Delegator observes 5% commission and calls `exit_delegation_pool_intent` on their current pool.
3. Staker calls `set_commission_commitment(max_commission: 9000, expiration_epoch: current+1)`.
4. Staker calls `set_commission(9000)` — commission is now 90%.
5. Delegator calls `switch_delegation_pool(to_staker, to_pool, amount)` — the call succeeds with no revert, and the delegator is now a member of a 90%-commission pool.

The exit window (default 1 week) gives the staker ample time to execute steps 3–4 without any need for mempool-level front-running.

### Impact Explanation

The delegator is now locked into a pool with a commission far higher than they accepted. Every epoch they remain in the pool, the staker captures a disproportionate share of their rewards. This constitutes **theft of unclaimed yield**. Additionally, to exit, the delegator must call `exit_delegation_pool_intent` again and wait through another full exit window, constituting **temporary freezing of funds**.

Both impacts are within the allowed scope.

### Likelihood Explanation

- No mempool front-running is required. The staker only needs to act during the exit window, which is at least one week.
- The staker can set up the commitment in the same block as or immediately after observing the delegator's intent on-chain.
- The attack is profitable for any staker willing to sacrifice reputation for short-term yield extraction.
- The only prerequisite is that no active commitment already exists, which the staker fully controls.

### Recommendation

Add a `max_commission` parameter to `switch_delegation_pool` (and propagate it through `switch_staking_delegation_pool` and `enter_delegation_pool_from_staking_contract`). Before completing the switch, assert that the destination pool's current commission does not exceed the caller's stated maximum:

```cairo
fn switch_delegation_pool(
    ref self: ContractState,
    to_staker: ContractAddress,
    to_pool: ContractAddress,
    amount: Amount,
    max_commission: Commission,   // <-- new parameter
) -> Amount {
    // ... existing checks ...
    let actual_commission = self.get_commission_from_staking_contract();
    assert!(actual_commission <= max_commission, Error::COMMISSION_TOO_HIGH);
    // ... rest of logic ...
}
```

This mirrors the standard slippage-protection pattern and ensures the transaction reverts rather than silently accepting worse terms.

### Proof of Concept

```
// Setup: staker has commission 500 (5%), delegator is in another pool.

// Step 1: Delegator signals intent to leave current pool.
pool_A.exit_delegation_pool_intent(amount: delegated_amount);

// Step 2: Staker sets a commitment allowing commission up to 9000 (90%).
staking.set_commission_commitment(max_commission: 9000, expiration_epoch: current_epoch + 1);

// Step 3: Staker raises commission to 9000 (90%).
staking.set_commission(commission: 9000);

// Step 4: Delegator switches — no revert, ends up in 90%-commission pool.
pool_A.switch_delegation_pool(to_staker: staker, to_pool: pool_B, amount: delegated_amount);

// Delegator now loses 90% of their yield each epoch instead of 5%.
// To exit they must wait another full exit window.
```

### Citations

**File:** src/staking/staking.cairo (L748-785)
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
        }
```

**File:** src/staking/staking.cairo (L1580-1590)
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
```

**File:** src/staking/staking.cairo (L1595-1597)
```text
            } else {
                assert!(commission < old_commission, "{}", Error::INVALID_COMMISSION);
            }
```

**File:** src/pool/pool.cairo (L379-429)
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

            // Emit event.
            self
                .emit(
                    Events::SwitchDelegationPool {
                        pool_member, new_delegation_pool: to_pool, amount,
                    },
                );

            pool_member_info.unpool_amount
        }
```
