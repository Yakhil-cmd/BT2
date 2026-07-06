### Title
Pool Contract `exit_delegation_pool_intent` Bypasses Pause Check When Staker Is Removed — (File: `src/pool/pool.cairo`)

---

### Summary

The `Pool` contract's `exit_delegation_pool_intent` function does not enforce the staking contract's paused state when the associated staker has been removed. This allows any pool member to start their exit-window countdown while the staking contract is paused, enabling them to withdraw funds immediately after the pause is lifted — bypassing the intended exit-window delay.

---

### Finding Description

The `Staking` contract has a pause mechanism (`is_paused` flag) enforced via `assert_is_unpaused()`. [1](#0-0) 

The protocol specification explicitly lists `CONTRACT_IS_PAUSED` as an error for `exit_delegation_pool_intent` in the Pool contract, with the pre-condition: *"Staking contract is unpaused."* [2](#0-1) 

In the Pool contract, `exit_delegation_pool_intent` delegates the pause enforcement to the staking contract by calling `undelegate_from_staking_contract_intent`, which calls `remove_from_delegation_pool_intent` on the staking contract (which checks pause). However, there is a critical branch: **when the staker has been removed** (`staker_removed == true`), the function skips the staking contract call entirely and returns `Time::now()` directly:

```cairo
fn undelegate_from_staking_contract_intent(
    self: @ContractState, pool_member: ContractAddress, amount: Amount,
) -> Timestamp {
    if !self.is_staker_active() {
        assert!(
            self.internal_pool_member_info(:pool_member).unpool_time.is_none(),
            "{}",
            Error::UNDELEGATE_IN_PROGRESS,
        );
        return Time::now();   // ← No pause check. Returns immediately.
    }
    // ... calls staking contract (which checks pause) only when staker is active
}
``` [3](#0-2) 

The `exit_delegation_pool_intent` function itself has no direct pause check: [4](#0-3) 

A grep confirms there are **zero** `CONTRACT_IS_PAUSED` checks anywhere in `src/pool/`: [5](#0-4) 

---

### Impact Explanation

When the staker is removed (after `unstake_action` completes, transferring funds into the pool contract), and the staking contract is subsequently paused:

1. A pool member calls `exit_delegation_pool_intent(amount)` on the pool contract.
2. Because `staker_removed == true`, the function sets `unpool_time = Time::now()` and `unpool_amount = amount` — **no pause check is performed**.
3. The exit-window countdown (`DEFAULT_EXIT_WAIT_WINDOW = 1 week`) begins during the pause period.
4. If the pause lasts ≥ 1 week, the pool member can call `exit_delegation_pool_action` immediately after the pause is lifted and withdraw funds without waiting the required exit window.

The comment in `exit_delegation_pool_action` confirms that when the staker is removed, the staking contract call does nothing (funds are already in the pool contract): [6](#0-5) 

**Impact**: Medium — griefing/protocol invariant violation. The pause mechanism is intended to freeze all operations. This bypass allows a pool member to circumvent the exit-window delay during a pause, enabling earlier-than-intended fund withdrawal after the pause is lifted. This violates the protocol's security invariant and could undermine the effectiveness of emergency pauses.

---

### Likelihood Explanation

**Medium.** The conditions required are:
1. A staker has completed `unstake_action` (staker removed, funds in pool contract) — a normal lifecycle event.
2. The staking contract is paused — an emergency security action.

Both conditions can realistically co-exist. A security incident may occur after a staker has already exited, leaving pool members with funds in the pool contract. A sophisticated pool member monitoring the chain can detect the pause and immediately call `exit_delegation_pool_intent` to start their countdown.

---

### Recommendation

Add an explicit pause check at the top of `exit_delegation_pool_intent` in `src/pool/pool.cairo` by querying the staking contract's pause state:

```cairo
fn exit_delegation_pool_intent(ref self: ContractState, amount: Amount) {
    // Add: check staking contract is not paused
    let staking_dispatcher = IStakingDispatcher {
        contract_address: self.staking_pool_dispatcher.contract_address.read(),
    };
    assert!(!staking_dispatcher.is_paused(), "{}", Error::CONTRACT_IS_PAUSED);
    // ... rest of function
}
```

This mirrors the pattern already used for `enter_delegation_pool` and `add_to_delegation_pool`, which enforce the pause indirectly via the staking contract call. Since the staker-removed path bypasses that call, the check must be explicit.

---

### Proof of Concept

1. Staker stakes STRK and opens a delegation pool via `set_open_for_delegation`.
2. Pool member calls `enter_delegation_pool(reward_address, amount)` — funds flow to staking contract.
3. Staker calls `unstake_intent()` then `unstake_action()` — staker is removed, pool funds transferred to pool contract, `staker_removed = true`.
4. Security agent calls `staking.pause()` — staking contract is now paused.
5. Pool member calls `pool.exit_delegation_pool_intent(amount)` — **succeeds** because `undelegate_from_staking_contract_intent` returns `Time::now()` without checking pause.
6. `pool_member_info.unpool_time = Time::now()` is written to storage. Exit window countdown begins.
7. After `DEFAULT_EXIT_WAIT_WINDOW` (1 week) elapses (still during or just after the pause), pool member calls `pool.exit_delegation_pool_action(pool_member)`.
8. The staking contract call (`remove_from_delegation_pool_action`) does nothing (staker removed, no intent registered). Funds transfer directly from pool contract to pool member.
9. Pool member has exited without waiting the required exit window post-unpause — the pause's protective delay is nullified.

### Citations

**File:** src/staking/staking.cairo (L1657-1659)
```text
        fn assert_is_unpaused(self: @ContractState) {
            assert!(!self.is_paused(), "{}", Error::CONTRACT_IS_PAUSED);
        }
```

**File:** docs/spec.md (L1961-1970)
```markdown
#### errors <!-- omit from toc -->
1. [POOL\_MEMBER\_DOES\_NOT\_EXIST](#pool_member_does_not_exist)
2. [AMOUNT\_TOO\_HIGH](#amount_too_high)
3. [UNDELEGATE\_IN\_PROGRESS](#undelegate_in_progress)
4. [CONTRACT\_IS\_PAUSED](#contract_is_paused)
#### pre-condition <!-- omit from toc -->
1. Pool member (caller) is listed in the contract.
2. `amount` is lower or equal to the total amount of the pool member (caller).
3. Pool member (caller) is not in an exit window or staker is active.
4. Staking contract is unpaused.
```

**File:** src/pool/pool.cairo (L181-220)
```text
    impl PoolImpl of IPool<ContractState> {
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

**File:** src/pool/pool.cairo (L256-293)
```text
        fn exit_delegation_pool_intent(ref self: ContractState, amount: Amount) {
            // Asserts.
            let pool_member = get_caller_address();
            let mut pool_member_info = self.internal_pool_member_info(:pool_member);
            let old_delegated_stake = self.get_last_member_balance(:pool_member);
            let total_amount = old_delegated_stake + pool_member_info.unpool_amount;
            assert!(amount <= total_amount, "{}", GenericError::AMOUNT_TOO_HIGH);

            // Notify the staking contract of the removal intent.
            let unpool_time = self.undelegate_from_staking_contract_intent(:pool_member, :amount);

            // Edit the pool member to reflect the removal intent, and write to storage.
            if amount.is_zero() {
                pool_member_info.unpool_time = Option::None;
            } else {
                pool_member_info.unpool_time = Option::Some(unpool_time);
            }
            pool_member_info.unpool_amount = amount;
            let new_delegated_stake = total_amount - amount;
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Update the pool member's balance checkpoint.
            self.set_member_balance(:pool_member, amount: new_delegated_stake);

            // Emit events.
            self
                .emit(
                    Events::PoolMemberExitIntent {
                        pool_member, exit_timestamp: unpool_time, amount,
                    },
                );
            self
                .emit(
                    Events::PoolMemberBalanceChanged {
                        pool_member, old_delegated_stake, new_delegated_stake,
                    },
                );
        }
```

**File:** src/pool/pool.cairo (L313-332)
```text
            // Perform removal action in the staking contract, receiving funds if needed.
            // Note that if the intent was done after the staker was removed (unstake_action),
            // the funds will already be in the pool contract, and the following call will do
            // nothing.
            let staking_pool_dispatcher = self.staking_pool_dispatcher.read();
            staking_pool_dispatcher
                .remove_from_delegation_pool_action(identifier: pool_member.into());

            let unpool_amount = pool_member_info.unpool_amount;
            pool_member_info.unpool_amount = Zero::zero();
            pool_member_info.unpool_time = Option::None;

            // Write the updated pool member info to storage.
            self.write_pool_member_info(:pool_member, :pool_member_info);

            // Transfer delegated amount to the pool member.
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: pool_member, amount: unpool_amount.into());

            unpool_amount
```

**File:** src/pool/pool.cairo (L637-663)
```text
        fn undelegate_from_staking_contract_intent(
            self: @ContractState, pool_member: ContractAddress, amount: Amount,
        ) -> Timestamp {
            if !self.is_staker_active() {
                // Don't allow intent if an intent is already in progress and the staker is erased.
                // Avoid the following flow:
                // 1. Member intent - moves member balance from the staker's `pool_amount` to
                // `UndelegateIntentKey`.
                // 2. Staker intent.
                // 3. Staker action - transfer the `pool_amount` from the staker to the pool
                // contract.
                // 4. Member intent - here it is no longer possible to move balance between the
                // `pool_amount` and the `UndelegateIntentKey`.
                assert!(
                    self.internal_pool_member_info(:pool_member).unpool_time.is_none(),
                    "{}",
                    Error::UNDELEGATE_IN_PROGRESS,
                );
                return Time::now();
            }
            let staking_pool_dispatcher = self.staking_pool_dispatcher.read();
            let staker_address = self.staker_address.read();
            staking_pool_dispatcher
                .remove_from_delegation_pool_intent(
                    :staker_address, identifier: pool_member.into(), :amount,
                )
        }
```
