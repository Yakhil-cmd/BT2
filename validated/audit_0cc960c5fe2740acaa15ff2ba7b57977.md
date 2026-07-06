### Title
Missing Expected-Commission Validation in `enter_delegation_pool` and `switch_delegation_pool` Allows Staker to Steal Delegator Yield - (File: src/pool/pool.cairo)

### Summary
The `enter_delegation_pool` and `switch_delegation_pool` functions in the Pool contract accept no `expected_commission` parameter. A staker who holds an active commission commitment can call `set_commission` to raise their commission to any value up to `max_commission` at any time — including immediately before a delegator's delegation transaction is included in a block. The delegator's transaction executes against the new, higher commission with no revert, and all future rewards are silently redistributed at the inflated rate, constituting theft of unclaimed yield.

### Finding Description

`enter_delegation_pool` in `src/pool/pool.cairo` takes only `reward_address` and `amount`: [1](#0-0) 

There is no check on the current commission. The commission is read dynamically from the staking contract at reward-distribution time, so whatever value the staker has set at that moment is the one applied to all future rewards.

`switch_delegation_pool` similarly routes funds to a destination pool without validating the destination pool's commission: [2](#0-1) 

The commission-increase path is gated by `set_commission_commitment`. Once a staker sets a commitment, `set_commission` allows raising the commission to any value ≤ `max_commission` while the commitment is active: [3](#0-2) 

The internal `update_commission` helper enforces this: with an active commitment the only constraint is `commission <= commitment.max_commission`; without one, commission must strictly decrease: [4](#0-3) 

The protocol's own inline note acknowledges the residual risk: [5](#0-4) 

`set_commission_commitment` allows a commitment window of up to one year: [6](#0-5) 

### Impact Explanation

A delegator who submits `enter_delegation_pool` after observing a 1 % commission pool will have their transaction execute against whatever commission the staker has set by the time the transaction is included. If the staker raised commission to `max_commission` (up to 100 %) in the same or a preceding block, the delegator earns a fraction of the yield they expected. The principal is recoverable only after the exit-wait window; all rewards accrued during the period at the inflated commission are permanently redirected to the staker. This is **theft of unclaimed yield** — a High-severity impact under the allowed scope.

### Likelihood Explanation

The attack requires the staker to hold an active commission commitment. Commitments are a standard, publicly callable feature. Once a commitment is set, the staker can raise commission at any block with a single transaction. Starknet's private mempool prevents classical mempool-sniping, but the staker can raise commission speculatively (e.g., right before advertising the pool to new delegators, or immediately after observing on-chain that a delegator has approved tokens to the pool contract). The exit-wait window of one week means a delegator who joins and then discovers the higher commission still loses one week of yield at the inflated rate before recovering principal.

### Recommendation

Add an `expected_commission` parameter to both `enter_delegation_pool` and `switch_delegation_pool` (for the destination pool). At the start of each function, read the current commission from the staking contract and revert if it does not match:

```cairo
fn enter_delegation_pool(
    ref self: ContractState,
    reward_address: ContractAddress,
    amount: Amount,
    expected_commission: Commission,   // <-- new
) {
    let current_commission = self.get_commission_from_staking_contract();
    assert!(current_commission == expected_commission, "{}", Error::COMMISSION_MISMATCH);
    // ... rest of existing logic
}
```

Apply the same guard to `switch_delegation_pool` before the destination pool is entered.

### Proof of Concept

1. Staker calls `set_commission_commitment(max_commission: 10000, expiration_epoch: current_epoch + 52)` — a one-year window at 100 % max commission.
2. Staker advertises their pool as having 1 % commission.
3. Delegator approves tokens to the pool contract and submits `enter_delegation_pool(reward_address, amount)`.
4. In the same epoch (or the preceding block), staker calls `set_commission(9999)` — valid because of the active commitment.
5. Delegator's transaction is included; `enter_delegation_pool` performs no commission check and succeeds.
6. All subsequent reward distributions to the pool are computed at 99.99 % commission; the delegator receives ≈ 0 yield.
7. Delegator must wait the full exit-wait window to recover principal, losing all yield accrued during that period. [1](#0-0) [3](#0-2) [6](#0-5)

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

**File:** src/pool/pool.cairo (L421-429)
```text
            self
                .emit(
                    Events::SwitchDelegationPool {
                        pool_member, new_delegation_pool: to_pool, amount,
                    },
                );

            pool_member_info.unpool_amount
        }
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

**File:** src/staking/staking.cairo (L1591-1609)
```text
                    assert!(
                        commission < old_commission, "{}", Error::COMMISSION_COMMITMENT_EXPIRED,
                    );
                }
            } else {
                assert!(commission < old_commission, "{}", Error::INVALID_COMMISSION);
            }

            // Update commission in storage.
            staker_pool_info.commission.write(Option::Some(commission));

            // Emit event.
            self
                .emit(
                    Events::CommissionChanged {
                        staker_address, old_commission, new_commission: commission,
                    },
                );
        }
```
