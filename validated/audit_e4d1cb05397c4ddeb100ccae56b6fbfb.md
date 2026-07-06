### Title
Missing Maximum Commission Guard in `enter_delegation_pool` and `switch_delegation_pool` Allows Staker Front-Running — (File: src/pool/pool.cairo)

### Summary
`enter_delegation_pool` and `switch_delegation_pool` in the delegation pool contract accept no `max_commission` parameter. The commission applied to a delegator's future yield is a mutable on-chain value controlled by the staker. A malicious staker can front-run either call by raising commission to the maximum (100 %) immediately before the delegator's transaction executes, causing all yield earned during the mandatory exit-window lock-up to be redirected to the staker.

### Finding Description
`enter_delegation_pool` (pool.cairo line 182) and `switch_delegation_pool` (pool.cairo line 379) both accept only the principal-related parameters (`reward_address`, `amount`, `to_staker`, `to_pool`). Neither accepts a `max_commission` bound. [1](#0-0) [2](#0-1) 

The commission is stored in the staking contract and read at reward-distribution time, not at entry time. The staking contract's `set_commission` imposes no time-lock: [3](#0-2) 

The codebase itself acknowledges this property with an explicit note: [4](#0-3) 

> **Note**: Current commission increase safeguards still allow for sudden commission changes.

The optional `set_commission_commitment` mechanism (staking.cairo line 748) is not enforced on the delegator's entry path; a staker who has never called it, or whose commitment has expired, can raise commission to `COMMISSION_DENOMINATOR` (10 000 = 100 %) at any time. [5](#0-4) 

### Impact Explanation
Once a delegator is inside the pool, their principal is locked until the exit-wait window elapses. During that window the staking contract calls `update_rewards_from_staking_contract` on the pool, passing rewards already net of commission. With commission at 100 %, the pool receives zero rewards; the delegator earns nothing while their capital is frozen. This constitutes **theft of unclaimed yield** (High) and **temporary freezing of funds** (High) for the duration of the exit window. [6](#0-5) 

### Likelihood Explanation
The attack requires a staker who is willing to act maliciously against their own delegators. On Starknet the sequencer processes transactions in order of submission/fee priority, so a staker who monitors the mempool (or who simply raises commission speculatively before advertising their pool) can reliably execute this. No privileged infrastructure access is needed beyond the staker's own key, which is already in scope as an unprivileged actor relative to the delegator.

### Recommendation
- **Short term:** Add a `max_commission: Commission` parameter to `enter_delegation_pool` and `switch_delegation_pool`. Assert `current_commission <= max_commission` at the start of each function, reverting if the staker has already raised commission above the caller's tolerance.
- **Long term:** Enforce a mandatory time-lock (e.g., one epoch) on all commission increases so that delegators always have an opportunity to exit before a higher commission takes effect, eliminating the front-running surface entirely.

### Proof of Concept

1. Staker S deploys a pool with commission = 5 % and advertises it.
2. Delegator D constructs and broadcasts `enter_delegation_pool(reward_address=D, amount=1000 STRK)`.
3. Before D's transaction is included, S calls `set_commission(commission=10000)` (100 %) with a higher fee, which executes first.
4. D's `enter_delegation_pool` executes successfully — no commission check exists. [7](#0-6) 

5. Every subsequent call to `update_rewards_from_staking_contract` passes `rewards = 0` to the pool (all rewards retained by S via commission). [6](#0-5) 

6. D calls `exit_delegation_pool_intent` and must wait the full exit-wait window (default one week, up to 12 weeks). [8](#0-7) 

7. During the entire lock-up period D earns zero yield; S captures 100 % of the rewards that D's stake generated. D recovers only their principal after the window expires.

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

**File:** src/pool/pool.cairo (L379-384)
```text
        fn switch_delegation_pool(
            ref self: ContractState,
            to_staker: ContractAddress,
            to_pool: ContractAddress,
            amount: Amount,
        ) -> Amount {
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

**File:** src/staking/staking.cairo (L73-73)
```text
    pub const COMMISSION_DENOMINATOR: Commission = 10000;
```

**File:** src/staking/staking.cairo (L74-75)
```text
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
