### Title
Delegator Has No Maximum-Commission Guard When Entering or Switching Delegation Pools — (`File: src/pool/pool.cairo`)

---

### Summary

`enter_delegation_pool` and `switch_delegation_pool` in `src/pool/pool.cairo` accept no `max_commission` parameter. A staker who holds an active `CommissionCommitment` can call `set_commission` to raise their commission to `max_commission` (up to 100 %) in the same block as a delegator's pool-entry or pool-switch transaction, silently redirecting all future yield to the staker. The protocol's own code comment acknowledges this gap: *"Current commission increase safeguards still allow for sudden commission changes."*

---

### Finding Description

**Relevant code path**

`enter_delegation_pool` (pool.cairo, lines 182–219) and `switch_delegation_pool` (pool.cairo, lines 379–429) both complete without ever reading or bounding the target pool's commission: [1](#0-0) [2](#0-1) 

The commission that will be applied to every future reward distribution is stored in `InternalStakerPoolInfoV2.commission` and is read live at reward-calculation time: [3](#0-2) 

`split_rewards_with_commission` then deducts the commission fraction before anything reaches the pool: [4](#0-3) 

`COMMISSION_DENOMINATOR` is 10 000, so a commission of 10 000 means 100 % of pool rewards go to the staker: [5](#0-4) 

**The commission-increase window**

Without a `CommissionCommitment`, `update_commission` only allows decreases: [6](#0-5) 

But with an *active* commitment the staker may set any value up to `max_commission`, including a value higher than the current commission: [7](#0-6) 

A commitment is active while `current_epoch < expiration_epoch`: [8](#0-7) 

`set_commission_commitment` allows `max_commission` up to `COMMISSION_DENOMINATOR` (100 %): [9](#0-8) 

The change is written to storage immediately with no time-lock or epoch delay: [10](#0-9) 

The protocol's own NatSpec acknowledges the gap: [11](#0-10) 

---

### Impact Explanation

A delegator who switches to (or freshly enters) a pool whose staker holds an active commitment with `max_commission = 10000` will have 100 % of their share of pool rewards redirected to the staker. Because the commission is applied at every `update_rewards` / `update_rewards_from_attestation_contract` call going forward, all future yield accrued while the delegator remains in the pool is stolen. This maps directly to **High: Theft of unclaimed yield**.

---

### Likelihood Explanation

The attack is reachable by any staker (an unprivileged protocol participant) who:

1. Calls `set_commission_commitment` with `max_commission = 10000` — permissionless, no admin role required.
2. Advertises a low commission to attract delegators.
3. Watches the mempool (or simply acts in the same block) for `switch_delegation_pool` / `enter_delegation_pool` calls targeting their pool.
4. Calls `set_commission(10000)` before the delegator's transaction is included.

Starknet sequencing is currently centralised, making transaction ordering predictable. Even without classic mempool front-running, the staker can raise commission in the epoch immediately before a delegator's switch completes, because the switch itself has a multi-step flow (intent → action) that spans at least one block.

---

### Recommendation

Add a `max_commission` parameter to both `enter_delegation_pool` and `switch_delegation_pool`. Before completing the entry or switch, assert that the target pool's current commission does not exceed the caller-supplied bound:

```cairo
fn enter_delegation_pool(
    ref self: ContractState,
    reward_address: ContractAddress,
    amount: Amount,
    max_commission: Commission,   // <-- new
) {
    ...
    let actual_commission = self.get_commission_from_staking_contract();
    assert!(actual_commission <= max_commission, "Commission exceeds max");
    ...
}
```

Apply the same guard in `switch_delegation_pool` before the call to `switch_staking_delegation_pool`.

---

### Proof of Concept

```
Epoch N:
  Staker calls set_commission(100)          // commission = 1 %
  Staker calls set_commission_commitment(
      max_commission = 10000,               // 100 %
      expiration_epoch = N + 10)

Epoch N+1:
  Delegator calls exit_delegation_pool_intent(amount) on old pool
  // Delegator's tx lands in the mempool / is about to be sequenced

  Staker observes and calls set_commission(10000)  // 100 % — succeeds because
                                                   // commitment is active and
                                                   // 10000 <= max_commission

  Delegator's switch_delegation_pool(to_staker, to_pool, amount) executes
  // No commission check → delegator is now in a 100 % commission pool

Epoch N+2 onwards:
  update_rewards called → split_rewards_with_commission(rewards, 10000)
  → commission_rewards = rewards, pool_rewards = 0
  → delegator.claim_rewards() returns 0
``` [12](#0-11) [13](#0-12) [4](#0-3)

### Citations

**File:** src/pool/pool.cairo (L182-219)
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

            self.set_member_balance(:pool_member, :amount);

            // Create the pool member record.
            self
                .pool_member_info
                .write(pool_member, VInternalPoolMemberInfoTrait::new_latest(:reward_address));

            // Emit events.
            self
                .emit(
                    Events::NewPoolMember { pool_member, staker_address, reward_address, amount },
                );
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake: Zero::zero(), new_delegated_stake: amount,
                    },
                );
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

**File:** src/staking/staking.cairo (L73-73)
```text
    pub const COMMISSION_DENOMINATOR: Commission = 10000;
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

**File:** src/staking/staking.cairo (L1573-1600)
```text
        fn update_commission(
            ref self: ContractState,
            staker_address: ContractAddress,
            staker_pool_info: StoragePath<Mutable<InternalStakerPoolInfoV2>>,
            old_commission: Commission,
            commission: Commission,
        ) {
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

**File:** src/staking/staking.cairo (L1964-1991)
```text
            let commission = staker_pool_info.commission();
            for (pool_contract, token_address) in staker_pool_info.pools {
                if !self.is_active_token(:token_address, epoch_id: curr_epoch) {
                    continue;
                }
                let pool_balance_curr_epoch = self
                    .get_staker_delegated_balance_at_epoch(
                        :staker_address, :pool_contract, epoch_id: curr_epoch,
                    );
                let (total_rewards, total_stake) = if token_address == STRK_TOKEN_ADDRESS {
                    (strk_total_rewards, strk_total_stake)
                } else {
                    (btc_total_rewards, btc_total_stake)
                };
                // Calculate rewards for this pool.
                let pool_rewards_including_commission = if total_stake.is_non_zero() {
                    mul_wide_and_div(
                        lhs: total_rewards,
                        rhs: pool_balance_curr_epoch.to_amount_18_decimals(),
                        div: total_stake.to_amount_18_decimals(),
                    )
                        .expect_with_err(err: InternalError::REWARDS_COMPUTATION_OVERFLOW)
                } else {
                    Zero::zero()
                };
                let (commission_rewards, pool_rewards) = split_rewards_with_commission(
                    rewards_including_commission: pool_rewards_including_commission, :commission,
                );
```

**File:** src/staking/staking.cairo (L2178-2182)
```text
        fn is_commission_commitment_active(
            self: @ContractState, commission_commitment: CommissionCommitment,
        ) -> bool {
            self.get_current_epoch() < commission_commitment.expiration_epoch
        }
```

**File:** src/staking/utils.cairo (L68-76)
```text
pub(crate) fn split_rewards_with_commission(
    rewards_including_commission: Amount, commission: Commission,
) -> (Amount, Amount) {
    let commission_rewards = compute_commission_amount_rounded_down(
        :rewards_including_commission, :commission,
    );
    let pool_rewards = rewards_including_commission - commission_rewards;
    (commission_rewards, pool_rewards)
}
```
