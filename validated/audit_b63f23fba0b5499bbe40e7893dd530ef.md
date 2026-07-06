### Title
Commission Frontrunning via `set_commission` Allows Staker to Steal Delegator Yield — (`src/pool/pool.cairo`, `src/staking/staking.cairo`)

---

### Summary

A staker holding an active `commission_commitment` can frontrun a delegator's `enter_delegation_pool` or `switch_delegation_pool` transaction by calling `set_commission` to raise the commission to `max_commission` (up to 100%). Because neither entry point accepts an `expected_commission` parameter, the delegator has no slippage protection and ends up locked into a pool that silently routes all their rewards to the staker.

---

### Finding Description

`set_commission` in `staking.cairo` enforces that commission can only decrease **unless** an active `commission_commitment` exists. When a commitment is active, the only constraints are:

```
commission <= commitment.max_commission
commission != old_commission
``` [1](#0-0) 

This means a staker can freely raise commission from 0% to `max_commission` (e.g. 10 000 = 100%) in a single transaction, at any time while the commitment is active.

Neither `enter_delegation_pool` nor `switch_delegation_pool` in `pool.cairo` accepts or validates an `expected_commission` argument:

```cairo
fn enter_delegation_pool(
    ref self: ContractState, reward_address: ContractAddress, amount: Amount,
) { ... }   // no commission check

fn switch_delegation_pool(
    ref self: ContractState,
    to_staker: ContractAddress,
    to_pool: ContractAddress,
    amount: Amount,
) -> Amount { ... }   // no commission check
``` [2](#0-1) [3](#0-2) 

The commission the delegator observed off-chain is therefore not guaranteed to be the commission in effect when their transaction executes.

---

### Impact Explanation

All pool rewards are split between the staker and delegators according to the commission rate stored in the staking contract at reward-distribution time: [4](#0-3) 

A commission of 10 000 (100%) means the staker receives the entire pool reward and delegators receive nothing. Every epoch the delegator remains in the pool, their accrued yield is silently redirected to the staker. This constitutes **theft of unclaimed yield** — a High-severity impact under the allowed scope.

---

### Likelihood Explanation

The precondition — an active `commission_commitment` — is entirely self-set by the staker via `set_commission_commitment`: [5](#0-4) 

A malicious staker can:
1. Call `set_commission_commitment(max_commission: 10000, expiration_epoch: current + N)`.
2. Immediately call `set_commission(0)` to advertise 0% commission and attract delegators.
3. Watch the mempool for incoming `enter_delegation_pool` / `switch_delegation_pool` transactions targeting their pool.
4. Frontrun with `set_commission(10000)`.
5. The delegator's transaction lands in a 100%-commission pool.

On Starknet the sequencer orders transactions; a staker who is also a sequencer, or who submits a higher-fee transaction in the same block, can reliably execute this ordering. Even without sequencer access, the attack is viable whenever the staker can observe pending transactions.

---

### Recommendation

Add an `expected_commission` parameter to both `enter_delegation_pool` and `switch_delegation_pool`. Before transferring funds, assert that the pool's current commission matches the caller's expectation:

```cairo
fn enter_delegation_pool(
    ref self: ContractState,
    reward_address: ContractAddress,
    amount: Amount,
    expected_commission: Commission,   // <-- add
) {
    let actual_commission = self.get_commission_from_staking_contract();
    assert!(actual_commission == expected_commission, "Unexpected commission");
    ...
}
```

Apply the same guard to `switch_delegation_pool`. This acts as a slippage check analogous to the fix recommended in the Frankencoin report.

---

### Proof of Concept

1. **Setup**: Staker calls `set_commission_commitment(max_commission: 10000, expiration_epoch: E+10)`, then `set_commission(0)`. Pool now advertises 0% commission.
2. **Victim**: Delegator reads commission = 0%, approves tokens, and submits `enter_delegation_pool(reward_address, amount)`.
3. **Frontrun**: Staker observes the pending transaction and submits `set_commission(10000)` with higher priority. Commission is now 100%.
4. **Victim lands**: Delegator's transaction executes. Funds are transferred to the pool. No revert occurs — there is no commission check.
5. **Harvest**: Each epoch, `update_rewards_from_staking_contract` is called. The pool's `compute_rewards_per_unit` credits the full reward to the staker's commission share. The delegator's `claim_rewards` returns 0 (or near 0). [6](#0-5) [7](#0-6) 

The delegator's principal is recoverable via `exit_delegation_pool_intent` / `exit_delegation_pool_action`, but all yield accrued during the period they were in the pool is permanently stolen.

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

**File:** src/pool/pool.cairo (L335-377)
```text
        fn claim_rewards(ref self: ContractState, pool_member: ContractAddress) -> Amount {
            // Asserts.
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let caller_address = get_caller_address();
            let reward_address = pool_member_info.reward_address;
            assert!(
                caller_address == pool_member || caller_address == reward_address,
                "{}",
                Error::POOL_CLAIM_REWARDS_FROM_UNAUTHORIZED_ADDRESS,
            );

            let until_checkpoint = self.get_current_checkpoint(:pool_member);

            // Calculate rewards and update entry_to_claim_from.
            let (mut rewards, updated_entry_to_claim_from) = self
                .calculate_rewards(
                    :pool_member,
                    from_checkpoint: pool_member_info.reward_checkpoint,
                    :until_checkpoint,
                    entry_to_claim_from: pool_member_info.entry_to_claim_from,
                );
            rewards += pool_member_info._unclaimed_rewards_from_v0;
            pool_member_info._unclaimed_rewards_from_v0 = Zero::zero();
            pool_member_info.entry_to_claim_from = updated_entry_to_claim_from;
            pool_member_info.reward_checkpoint = until_checkpoint;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer rewards to the pool member.
            let reward_token = IERC20Dispatcher { contract_address: STRK_TOKEN_ADDRESS };
            reward_token.checked_transfer(recipient: reward_address, amount: rewards.into());

            // Emit event.
            self
                .emit(
                    Events::PoolMemberRewardClaimed {
                        pool_member, reward_address, amount: rewards,
                    },
                );

            rewards
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

**File:** src/pool/pool.cairo (L569-587)
```text
        fn update_rewards_from_staking_contract(
            ref self: ContractState, rewards: Amount, pool_balance: Amount,
        ) {
            self.assert_caller_is_staking_contract();

            // `rewards_info` is initialized in the constructor or in the upgrade proccess,
            // so unwrapping should be safe.
            let (_, last) = self.cumulative_rewards_trace.last().unwrap();
            self
                .cumulative_rewards_trace
                .insert(
                    key: self.get_current_epoch(),
                    value: last
                        + self
                            .compute_rewards_per_unit(
                                staking_rewards: rewards, total_stake: pool_balance,
                            ),
                );
        }
```

**File:** src/pool/pool.cairo (L935-948)
```text
        fn get_commission_from_staking_contract(self: @ContractState) -> Commission {
            if self.staker_removed.read() {
                return Zero::zero();
            }
            let staking_dispatcher = IStakingDispatcher {
                contract_address: self.staking_pool_dispatcher.contract_address.read(),
            };
            // The staker must have commission since it has a pool (this contract). So unwrap is
            // safe.
            staking_dispatcher
                .staker_pool_info(staker_address: self.staker_address.read())
                .commission
                .unwrap()
        }
```
