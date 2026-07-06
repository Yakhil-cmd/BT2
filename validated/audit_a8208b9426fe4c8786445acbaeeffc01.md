### Title
Staker Can Front-Run Delegator's `enter_delegation_pool` / `add_to_delegation_pool` by Raising Commission Under an Active Commitment - (File: src/pool/pool.cairo)

---

### Summary

`enter_delegation_pool` and `add_to_delegation_pool` in `src/pool/pool.cairo` accept no `max_commission` parameter. When a staker holds an active `commission_commitment` (set via `set_commission_commitment`), the protocol explicitly permits the staker to **raise** their commission up to `max_commission` at any moment. A delegator who submits a delegation transaction based on the currently-visible commission has no on-chain protection against the staker changing commission to a higher value before the transaction is included, causing the delegator to earn far less yield than expected.

---

### Finding Description

The `update_commission` internal function in `src/staking/staking.cairo` enforces two distinct code paths:

1. **No active commitment** – commission can only decrease (`commission < old_commission`).
2. **Active commitment** – commission can be set to **any** value `<= commission_commitment.max_commission`, including values **higher** than the current commission, as long as it differs from `old_commission`. [1](#0-0) 

`set_commission_commitment` explicitly requires `max_commission >= current_commission`, meaning the commitment is designed to allow future increases: [2](#0-1) 

The protocol itself acknowledges this gap with a developer note directly above `set_commission_commitment`: [3](#0-2) 

Neither `enter_delegation_pool` nor `add_to_delegation_pool` in the pool contract accept a `max_commission` argument, so a delegator cannot express a commission ceiling at delegation time: [4](#0-3) [5](#0-4) 

---

### Impact Explanation

Commission is the fraction of pool rewards the staker retains before distributing the remainder to delegators. If a staker raises commission from 5 % to 50 % immediately before a delegator's delegation transaction is included, the delegator will earn 50 % less yield than they anticipated for every epoch they remain in the pool. This constitutes **theft of unclaimed yield** (High impact under the allowed scope).

---

### Likelihood Explanation

The attack requires the staker to have previously called `set_commission_commitment` with a `max_commission` materially above the current commission. This is a legitimate, publicly-visible on-chain action. A rational malicious staker would:

1. Advertise a low commission (e.g., 5 %) to attract delegators.
2. Quietly set a commitment with `max_commission = 50 %` (or up to 100 %).
3. Monitor for incoming `enter_delegation_pool` or `add_to_delegation_pool` transactions.
4. Submit `set_commission(max_commission)` in the same or a preceding block.

On Starknet the sequencer controls ordering, so strict mempool front-running is not required; the staker only needs to submit the commission-raise transaction before the delegator's transaction is sequenced. Because the commitment is public and the window can span up to one year (`expiration_epoch - current_epoch <= epochs_in_year()`), the attack surface is persistent. [6](#0-5) 

---

### Recommendation

Add a `max_commission: Commission` parameter to both `enter_delegation_pool` and `add_to_delegation_pool`. At the start of each function, read the current commission from the staking contract and revert if it exceeds the caller-supplied ceiling:

```rust
fn enter_delegation_pool(
    ref self: ContractState,
    reward_address: ContractAddress,
    amount: Amount,
    max_commission: Commission,   // <-- new
) {
    // existing asserts …
    let current_commission = self.get_staker_commission();
    assert!(current_commission <= max_commission, Error::COMMISSION_EXCEEDS_MAX);
    // … rest of function
}
```

Apply the same guard to `add_to_delegation_pool`. This mirrors the fix applied in the reference report (`expectedPaymentToken` / `maxTotal` parameters on `mint()`).

---

### Proof of Concept

**Setup**

- Bob deploys a staking pool with commission = 500 (5 %).
- Bob calls `set_commission_commitment(max_commission: 5000, expiration_epoch: current + 365)`.
  This is publicly visible on-chain but easy to overlook.

**Attack**

1. Alice inspects the pool, sees commission = 5 %, and approves the pool contract to spend her STRK.
2. Alice submits `enter_delegation_pool(reward_address: alice_reward, amount: 1_000_000)`.
3. Before Alice's transaction is sequenced, Bob calls `set_commission(commission: 5000)` (50 %).
   This succeeds because an active commitment with `max_commission = 5000` exists. [7](#0-6) 
4. Alice's transaction is included. Her funds are transferred and her pool-member record is created — but the pool now operates at 50 % commission. [8](#0-7) 
5. For every subsequent epoch, Alice receives only 50 % of her proportional pool rewards instead of the 95 % she expected. The remaining 50 % accrues to Bob.

Alice has no on-chain recourse; the transaction succeeded and her funds are locked until she completes the exit-intent / exit-action cycle.

### Citations

**File:** src/staking/staking.cairo (L745-747)
```text
        /// **Note**: Current commission increase safeguards still allow for sudden commission
        /// changes.
        /// **Note**: Updating epoch info can impact the commission commitment expiration date.
```

**File:** src/staking/staking.cairo (L769-778)
```text
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

**File:** src/pool/pool.cairo (L182-184)
```text
        fn enter_delegation_pool(
            ref self: ContractState, reward_address: ContractAddress, amount: Amount,
        ) {
```

**File:** src/pool/pool.cairo (L196-206)
```text
            // Transfer funds from the delegator to the staking contract.
            let staker_address = self.staker_address.read();
            transfer_from_delegator(:pool_member, :amount, :token_dispatcher);
            self.transfer_to_staking_contract(:amount, :token_dispatcher, :staker_address);

            self.set_member_balance(:pool_member, :amount);

            // Create the pool member record.
            self
                .pool_member_info
                .write(pool_member, VInternalPoolMemberInfoTrait::new_latest(:reward_address));
```

**File:** src/pool/pool.cairo (L221-223)
```text
        fn add_to_delegation_pool(
            ref self: ContractState, pool_member: ContractAddress, amount: Amount,
        ) -> Amount {
```
