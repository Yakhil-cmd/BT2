### Title
Staker Can Front-Run Delegator's `enter_delegation_pool` to Silently Increase Commission Rate — (File: src/pool/pool.cairo)

---

### Summary

`enter_delegation_pool` and `add_to_delegation_pool` accept no `max_commission` parameter. A staker who holds an active `commission_commitment` can atomically front-run a delegator's delegation transaction by calling `set_commission` to raise the commission up to `max_commission` (potentially 100 %). The delegator's funds are locked in the pool at the inflated rate, and all future rewards are silently redirected to the staker until the delegator discovers the change and completes the exit window.

---

### Finding Description

**Vulnerable entry points**

`enter_delegation_pool` in `src/pool/pool.cairo` (line 182) and `add_to_delegation_pool` (line 221) accept only `reward_address` / `amount`. Neither accepts a `max_commission` guard. [1](#0-0) 

The commission a delegator will actually pay is not fixed at delegation time. It is read dynamically from the staking contract every time it is needed: [2](#0-1) 

**Commission-increase path**

Normally `set_commission` can only *decrease* commission: [3](#0-2) 

However, when an active `commission_commitment` exists, the staker may set commission to **any value up to `max_commission`** (which can be as high as `COMMISSION_DENOMINATOR` = 10 000, i.e. 100 %): [4](#0-3) 

The `set_commission_commitment` function allows `max_commission` up to `COMMISSION_DENOMINATOR` and requires only that it is ≥ the current commission: [5](#0-4) 

The codebase itself acknowledges this risk in a comment directly above `set_commission_commitment`: [6](#0-5) 

**Attack sequence**

1. Staker sets commission to 5 % and calls `set_commission_commitment(max_commission=10000, expiration_epoch=current+N)`.
2. Delegator observes 5 % commission and submits `enter_delegation_pool(reward_address, amount)`.
3. Staker sees the pending transaction in the mempool and front-runs it with `set_commission(10000)` — valid because an active commitment allows it.
4. Delegator's transaction executes; they are now a pool member under 100 % commission.
5. All future rewards for that pool are paid entirely to the staker as commission; the delegator receives zero yield.
6. The delegator must call `exit_delegation_pool_intent` and wait the full `exit_wait_window` before recovering principal, earning nothing during that period.

---

### Impact Explanation

**High — Theft of unclaimed yield.**

The staker captures 100 % of the delegator's share of epoch rewards. The delegator's principal is not lost, but every unit of yield they would have earned is redirected to the staker for as long as the delegator remains in the pool. The delegator has no on-chain mechanism to enforce the commission rate they observed before submitting the transaction.

---

### Likelihood Explanation

**Medium.**

- The staker must have previously called `set_commission_commitment` with a high `max_commission`. This is a deliberate, one-time setup step that costs only a transaction.
- Starknet transactions are publicly visible before inclusion (sequencer mempool), making front-running feasible.
- The attack is profitable for any staker willing to sacrifice delegator trust for short-term yield extraction.
- No privileged role beyond being a registered staker is required.

---

### Recommendation

1. **Add a `max_commission` parameter** to `enter_delegation_pool` and `add_to_delegation_pool`. Revert if the current commission exceeds the caller-supplied limit at execution time.
2. **Add a deadline parameter** (block number or timestamp) to both functions so that a stale transaction cannot be executed after the delegator's intent has expired.
3. Consider enforcing a **time-lock** between a commission increase (via commitment) and when it takes effect, giving delegators an opportunity to exit before the new rate applies.

---

### Proof of Concept

```
// 1. Staker initialises with 5% commission and sets a commitment allowing up to 100%.
staking.set_commission(commission: 500);
staking.set_commission_commitment(max_commission: 10000, expiration_epoch: current + 10);

// 2. Delegator approves and submits enter_delegation_pool — visible in mempool.
token.approve(spender: pool, amount: DELEGATE_AMOUNT);
pool.enter_delegation_pool(reward_address: delegator_reward, amount: DELEGATE_AMOUNT);
// ← staker front-runs here ↓

// 3. Staker's front-run transaction (higher gas / priority):
staking.set_commission(commission: 10000);   // 100% — valid under active commitment

// 4. Delegator's transaction now executes at 100% commission.
// pool_member_info_v1.commission == 10000

// 5. After one epoch the delegator claims rewards:
pool.claim_rewards(pool_member: delegator);
// Returns 0 — all yield was taken as commission by the staker.
```

The root cause is confirmed at: [1](#0-0) [4](#0-3)

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
