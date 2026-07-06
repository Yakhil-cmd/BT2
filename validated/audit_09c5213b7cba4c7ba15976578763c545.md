### Title
Missing Maximum Commission Guard in `switch_delegation_pool` / `enter_delegation_pool` Enables Staker Front-Running - (File: src/pool/pool.cairo)

### Summary
`switch_delegation_pool` and `enter_delegation_pool` in `Pool.cairo` accept no `max_commission` parameter. A staker who holds an active `commission_commitment` with a high `max_commission` can atomically front-run a delegator's pool-entry or pool-switch transaction by calling `set_commission` to raise their commission to the committed ceiling. The delegator ends up locked into a pool with a far higher commission than they observed, and all future yield is diverted to the staker.

### Finding Description

The `switch_delegation_pool` function signature is:

```rust
fn switch_delegation_pool(
    ref self: ContractState,
    to_staker: ContractAddress,
    to_pool: ContractAddress,
    amount: Amount,
) -> Amount
``` [1](#0-0) 

No `max_commission` (or equivalent slippage guard) is accepted. The same is true for `enter_delegation_pool`:

```rust
fn enter_delegation_pool(
    ref self: ContractState, reward_address: ContractAddress, amount: Amount,
)
``` [2](#0-1) 

The commission a delegator will pay is determined at reward-distribution time by whatever value is stored in the staking contract at that moment. A staker can change their commission at any time via `set_commission`, subject to the following rule in `update_commission`:

```rust
if self.is_commission_commitment_active(:commission_commitment) {
    assert!(
        commission <= commission_commitment.max_commission, ...
    );
    assert!(commission != old_commission, ...);
}
``` [3](#0-2) 

When a `commission_commitment` is active, the only constraint is `commission <= max_commission`. If `max_commission > current_commission`, the staker can **increase** their commission to any value up to `max_commission`. The codebase itself acknowledges this:

```
/// **Note**: Current commission increase safeguards still allow for sudden commission changes.
``` [4](#0-3) 

`set_commission_commitment` allows any staker to set `max_commission` up to 10 000 (100 %):

```rust
assert!(max_commission <= COMMISSION_DENOMINATOR, "{}", Error::COMMISSION_OUT_OF_RANGE);
...
assert!(current_commission <= max_commission, "{}", Error::MAX_COMMISSION_TOO_LOW);
``` [5](#0-4) 

### Impact Explanation

When a delegator calls `switch_delegation_pool` or `enter_delegation_pool`, the commission they will pay is not bounded by anything they supply. A staker who has pre-positioned a `commission_commitment` with `max_commission = 10000` can front-run the delegator's transaction, raising their commission from e.g. 1 % to 100 %. Every unit of STRK reward subsequently earned by the delegator's stake is transferred entirely to the staker's reward address. The delegator's principal is recoverable only after the exit-wait window, but all yield accrued in the interim is permanently stolen.

This maps to the allowed impact: **High — Theft of unclaimed yield**.

### Likelihood Explanation

The attack requires a staker to:
1. Call `set_commission_commitment` with a high `max_commission` (publicly visible on-chain, but not checked by the pool-entry functions).
2. Observe a pending `switch_delegation_pool` or `enter_delegation_pool` transaction in the mempool (or simply raise commission preemptively before advertising a low rate).
3. Call `set_commission` in the same block or before the delegator's transaction lands.

Step 1 is a one-time setup. Steps 2–3 are standard front-running. On Starknet, sequencer ordering is controlled, but the staker can still submit `set_commission` in the same block before the delegator's call. The attack is deliberate and profitable, making it a realistic threat from a malicious staker.

### Recommendation

Add a `max_commission: Commission` parameter to both `switch_delegation_pool` and `enter_delegation_pool`. Before completing the operation, assert that the pool's current commission does not exceed the caller-supplied bound:

```rust
fn switch_delegation_pool(
    ref self: ContractState,
    to_staker: ContractAddress,
    to_pool: ContractAddress,
    amount: Amount,
    max_commission: Commission,   // <-- new
) -> Amount {
    // existing asserts ...
    let current_commission = /* read from staking contract */;
    assert!(current_commission <= max_commission, Error::COMMISSION_TOO_HIGH);
    // ... rest of logic
}
```

Apply the same guard to `enter_delegation_pool` and `add_to_delegation_pool`.

### Proof of Concept

1. Staker Eve deploys with commission = 100 (1 %).
2. Eve calls `set_commission_commitment(max_commission: 10000, expiration_epoch: current + 10)`.
3. Alice observes Eve's pool advertising 1 % commission and submits `switch_delegation_pool(to_staker: Eve, to_pool: Eve_pool, amount: X)`.
4. Eve's bot detects Alice's pending transaction and submits `set_commission(commission: 10000)` with higher priority (or in the same block before Alice's tx).
5. Alice's `switch_delegation_pool` executes. The pool now has 100 % commission.
6. Every attestation reward earned on Alice's `X` tokens is split: 100 % to Eve, 0 % to Alice.
7. Alice must wait the full exit-wait window to recover her principal; all yield during that window is lost to Eve.

The root cause — no `max_commission` guard in `switch_delegation_pool` — is at: [6](#0-5) 

The enabling mechanism — commission increase via active commitment — is at: [3](#0-2)

### Citations

**File:** src/pool/interface.cairo (L30-32)
```text
    fn enter_delegation_pool(
        ref self: TContractState, reward_address: ContractAddress, amount: Amount,
    );
```

**File:** src/pool/interface.cairo (L155-160)
```text
    fn switch_delegation_pool(
        ref self: TContractState,
        to_staker: ContractAddress,
        to_pool: ContractAddress,
        amount: Amount,
    ) -> Amount;
```

**File:** src/staking/staking.cairo (L745-746)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
```

**File:** src/staking/staking.cairo (L752-770)
```text
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
