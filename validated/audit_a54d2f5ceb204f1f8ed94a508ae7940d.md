### Title
Missing Max-Commission Guard on `enter_delegation_pool()` and `switch_delegation_pool()` Allows Stale Transactions to Execute at Unfavorable Commission Rates — (`File: src/pool/pool.cairo`)

---

### Summary

`enter_delegation_pool()` and `switch_delegation_pool()` in `pool.cairo` accept no `max_commission` or deadline parameter. A staker who holds an active `commission_commitment` can increase their commission to any value up to `max_commission` at any time. A pool member's pending delegation transaction can therefore be front-run or simply land after a commission spike, silently locking the member into a pool with a far higher commission rate than they intended.

---

### Finding Description

`enter_delegation_pool()` takes only `reward_address` and `amount`: [1](#0-0) 

`switch_delegation_pool()` takes only `to_staker`, `to_pool`, and `amount`: [2](#0-1) 

Neither function checks the pool's current commission against any caller-supplied bound before transferring funds and committing the membership.

The commission a staker charges is normally only allowed to decrease: [3](#0-2) 

However, when a staker holds an **active** `commission_commitment`, `update_commission` permits any value up to `max_commission`, which can be arbitrarily higher than the current commission: [4](#0-3) 

The protocol itself acknowledges this gap with an explicit code comment: [5](#0-4) 

A staker can therefore set a `commission_commitment` with a high `max_commission` (e.g. 9 000 / 10 000 = 90 %) and keep the current commission low to attract delegators. When a delegation transaction appears in the mempool, the staker calls `set_commission(9000)` before it lands.

---

### Impact Explanation

The pool member is enrolled in the pool at the elevated commission rate. Every reward epoch thereafter, the staker retains up to 90 % of the pool's rewards instead of the rate the member observed when signing. The member must still wait through the full `exit_wait_window` (default 1 week, up to 12 weeks) before recovering their principal, during which rewards continue to accrue at the inflated rate. This constitutes **ongoing theft of unclaimed yield** for the duration of the exit window.

Allowed impact matched: **High — Theft of unclaimed yield**.

---

### Likelihood Explanation

1. A staker sets `commission_commitment` with a high `max_commission` — a single permissionless call available to any staker with a pool.
2. The staker monitors the Starknet mempool (or simply races in the same block, since the sequencer orders transactions) for `enter_delegation_pool` / `switch_delegation_pool` calls targeting their pool.
3. The staker calls `set_commission(max_commission)` in the same block or before the victim's transaction is included.

No privileged access, leaked key, or external dependency is required. The attacker is the staker themselves, a role any address can assume. The `commission_commitment` mechanism is a documented, publicly callable feature.

---

### Recommendation

Add a `max_commission` guard parameter to both functions and revert if the pool's current commission exceeds it at execution time:

```cairo
fn enter_delegation_pool(
    ref self: ContractState,
    reward_address: ContractAddress,
    amount: Amount,
+   max_commission: Commission,   // caller-supplied upper bound
) {
+   let current_commission = self.get_commission_from_staking_contract();
+   assert!(current_commission <= max_commission, Error::COMMISSION_TOO_HIGH);
    ...
}

fn switch_delegation_pool(
    ref self: ContractState,
    to_staker: ContractAddress,
    to_pool: ContractAddress,
    amount: Amount,
+   max_commission: Commission,
) -> Amount {
+   // read commission of to_pool's staker and assert <= max_commission
    ...
}
```

Optionally, a `deadline` (block number or timestamp) parameter can be added alongside `max_commission` to reject transactions that have been pending too long regardless of commission.

---

### Proof of Concept

1. **Setup**: Staker S deploys a STRK pool with commission = 100 (1 %). Staker S calls `set_commission_commitment(max_commission: 9000, expiration_epoch: current + 10)`.
2. **Victim**: Pool member Alice signs `enter_delegation_pool(reward_address, amount=1_000_000_STRK)` and submits it to the Starknet sequencer with a low fee.
3. **Attack**: Before Alice's transaction is sequenced, Staker S calls `set_commission(commission: 9000)`. Because an active `commission_commitment` exists with `max_commission = 9000`, `update_commission` allows the increase: [4](#0-3) 
4. **Execution**: Alice's `enter_delegation_pool` executes with no commission check: [6](#0-5) 
   Alice is now a pool member at 90 % commission.
5. **Impact**: Alice must call `exit_delegation_pool_intent` and wait the full exit window before recovering her stake. During that window all rewards are split 90/10 in favour of Staker S. Alice has no on-chain recourse to reject the transaction after the fact.

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

**File:** src/staking/staking.cairo (L745-746)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
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

**File:** src/staking/staking.cairo (L1595-1597)
```text
            } else {
                assert!(commission < old_commission, "{}", Error::INVALID_COMMISSION);
            }
```
