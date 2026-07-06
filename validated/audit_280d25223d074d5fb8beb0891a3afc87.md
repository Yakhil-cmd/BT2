### Title
Live Token Balance Used in `request_funds` Suppresses L1 Mint Requests via Direct Transfer - (`src/reward_supplier/reward_supplier.cairo`)

---

### Summary

The `request_funds` internal function in `RewardSupplier` reads the contract's **live token balance** (`balance_of(get_contract_address())`) to compute available credit when deciding whether to send a mint request to L1. An unprivileged attacker can directly transfer STRK tokens to the `RewardSupplier` contract to artificially inflate this credit, suppressing legitimate L1 mint requests. When the donated tokens are eventually consumed by reward payments, the contract may lack sufficient balance to fulfill `claim_rewards` calls, temporarily freezing unclaimed yield for stakers and delegators.

---

### Finding Description

In `request_funds` (lines 301–331 of `src/reward_supplier/reward_supplier.cairo`), the credit calculation reads the live ERC-20 balance:

```rust
fn request_funds(ref self: ContractState, unclaimed_rewards: Amount) {
    let token_dispatcher = self.token_dispatcher.read();
    let balance: Amount = token_dispatcher
        .balance_of(account: get_contract_address())   // <-- live balance, manipulable
        .try_into()
        .expect_with_err(InternalError::BALANCE_ISNT_AMOUNT_TYPE);

    let mut l1_pending_requested_amount = self.l1_pending_requested_amount.read();
    let credit = balance + l1_pending_requested_amount;
    let debit = unclaimed_rewards;

    let base_mint_amount = self.base_mint_amount.read();
    let threshold = compute_threshold(base_mint_amount);
    if credit < debit + threshold {
        // ... send L1 mint request
    }
    self.l1_pending_requested_amount.write(l1_pending_requested_amount);
}
``` [1](#0-0) 

The only mechanism that decreases `l1_pending_requested_amount` is `on_receive`, which is gated to the StarkGate bridge address:

```rust
fn on_receive(...) {
    assert!(get_caller_address() == self.starkgate_address.read(), ...);
    ...
    l1_pending_requested_amount -= amount_u128;
    ...
}
``` [2](#0-1) 

A direct ERC-20 transfer to the `RewardSupplier` contract increases `balance_of(get_contract_address())` without triggering `on_receive` and without updating any internal accounting variable. This inflates `credit`, causing the `credit < debit + threshold` guard to remain false, and no L1 mint request is emitted.

The `claim_rewards` function then drains the contract's actual token balance over time:

```rust
fn claim_rewards(ref self: ContractState, amount: Amount) {
    ...
    self.unclaimed_rewards.write(unclaimed_rewards - amount);
    token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
}
``` [3](#0-2) 

When the donated tokens are exhausted and no L1 requests were made during the donation window, `checked_transfer` will revert due to insufficient balance, blocking reward distribution.

---

### Impact Explanation

**Temporary freezing of unclaimed yield.** When the donated tokens are consumed and no L1 mint requests were issued during the suppression window, the `RewardSupplier` contract holds zero (or insufficient) STRK balance while `unclaimed_rewards` remains positive. The staking contract's call to `claim_rewards` will revert, preventing it from distributing earned rewards to stakers and delegators until a new L1 mint request is processed and tokens arrive via StarkGate. The freeze duration equals the L1→L2 message processing latency.

---

### Likelihood Explanation

Any unprivileged actor can execute this by calling `transfer` on the STRK ERC-20 contract with the `RewardSupplier` address as recipient. No special role, key, or bridge access is required. The cost to the attacker is the donated tokens themselves. A modest donation timed to coincide with a low-balance period (e.g., just after a large `claim_rewards` batch) can suppress L1 requests for multiple epochs.

---

### Recommendation

Replace the live `balance_of` call in `request_funds` with an internally tracked balance variable (analogous to Uniswap V2's `reserve0`/`reserve1`). Increment this variable only in `on_receive` (when tokens legitimately arrive from StarkGate) and decrement it in `claim_rewards` (when tokens are sent to the staking contract). Use this tracked balance instead of `balance_of(get_contract_address())` for the credit calculation:

```rust
// Add to storage:
tracked_balance: Amount,

// In on_receive: self.tracked_balance.write(self.tracked_balance.read() + amount_u128);
// In claim_rewards: self.tracked_balance.write(self.tracked_balance.read() - amount);
// In request_funds: let balance = self.tracked_balance.read();
```

This ensures that tokens donated directly to the contract do not affect the L1 mint request logic.

---

### Proof of Concept

1. Protocol is in steady state: `balance_of(reward_supplier) = 1000 STRK`, `unclaimed_rewards = 1000`, `l1_pending_requested_amount = 0`.
2. Attacker calls `STRK.transfer(reward_supplier, 50_000 STRK)` directly.
3. `balance_of(reward_supplier)` is now `51_000 STRK`. No internal state changes.
4. Over the next N epochs, the staking contract calls `update_unclaimed_rewards_from_staking_contract(epoch_rewards)` each epoch. Each call invokes `request_funds(unclaimed_rewards)`.
5. Inside `request_funds`: `credit = 51_000 + 0 = 51_000`. Even as `unclaimed_rewards` grows, `credit >= debit + threshold` holds for many epochs → **no L1 mint requests are sent**.
6. Each epoch, `claim_rewards` drains the balance. After enough epochs, `balance_of(reward_supplier) ≈ 0`.
7. The next `claim_rewards(amount)` call issues `checked_transfer` with insufficient balance → **reverts**.
8. Stakers and delegators cannot claim earned rewards. The freeze persists until `request_funds` is triggered again (on the next `update_unclaimed_rewards_from_staking_contract` call), an L1 mint request is sent, and StarkGate delivers the tokens.

### Citations

**File:** src/reward_supplier/reward_supplier.cairo (L204-220)
```text
        // This function is called by the staking contract, claiming an amount of owed rewards.
        fn claim_rewards(ref self: ContractState, amount: Amount) {
            // Asserts.
            let staking_contract = self.staking_contract.read();
            assert!(
                get_caller_address() == staking_contract,
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );
            let unclaimed_rewards = self.unclaimed_rewards.read();
            assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);

            // Update unclaimed_rewards and transfer the requested rewards to the staking contract.
            self.unclaimed_rewards.write(unclaimed_rewards - amount);
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
        }
```

**File:** src/reward_supplier/reward_supplier.cairo (L222-254)
```text
        fn on_receive(
            ref self: ContractState,
            l2_token: ContractAddress,
            amount: u256,
            depositor: EthAddress,
            message: Span<felt252>,
        ) -> bool {
            // Note that the deposit can be done by anyone (not just the L1 reward supplier), so
            // depositor is not checked.

            // These messages accepted only from the token bridge.
            assert!(
                get_caller_address() == self.starkgate_address.read(),
                "{}",
                Error::ON_RECEIVE_NOT_FROM_STARKGATE,
            );
            // The bridge may serve multiple tokens, only the correct token may be received.
            assert!(
                l2_token == self.token_dispatcher.contract_address.read(),
                "{}",
                Error::UNEXPECTED_TOKEN,
            );
            let amount_u128: Amount = amount
                .try_into()
                .expect_with_err(GenericError::AMOUNT_TOO_HIGH);
            let mut l1_pending_requested_amount = self.l1_pending_requested_amount.read();
            if amount_u128 > l1_pending_requested_amount {
                self.l1_pending_requested_amount.write(Zero::zero());
            } else {
                l1_pending_requested_amount -= amount_u128;
                self.l1_pending_requested_amount.write(l1_pending_requested_amount);
            }
            true
```

**File:** src/reward_supplier/reward_supplier.cairo (L301-331)
```text
        fn request_funds(ref self: ContractState, unclaimed_rewards: Amount) {
            // Read current balance.
            let token_dispatcher = self.token_dispatcher.read();
            let balance: Amount = token_dispatcher
                .balance_of(account: get_contract_address())
                .try_into()
                .expect_with_err(InternalError::BALANCE_ISNT_AMOUNT_TYPE);

            // Calculate credit, which is the contract's balance plus the amount already requested
            // from L1, and the debit, which is the unclaimed rewards.
            let mut l1_pending_requested_amount = self.l1_pending_requested_amount.read();
            let credit = balance + l1_pending_requested_amount;
            let debit = unclaimed_rewards;

            // If there isn't enough credit to cover the debit + threshold, request funds.
            let base_mint_amount = self.base_mint_amount.read();
            let threshold = compute_threshold(base_mint_amount);
            if credit < debit + threshold {
                let diff = debit + threshold - credit;
                let num_msgs = ceil_of_division(dividend: diff, divisor: base_mint_amount);
                let total_amount = num_msgs * base_mint_amount;
                for _ in 0..num_msgs {
                    self.send_mint_request_to_l1_reward_supplier();
                }
                self.emit(Events::MintRequest { total_amount, num_msgs });
                l1_pending_requested_amount += total_amount;
            }

            // Commit to storage the requested amount, which is now part of the credit.
            self.l1_pending_requested_amount.write(l1_pending_requested_amount);
        }
```
