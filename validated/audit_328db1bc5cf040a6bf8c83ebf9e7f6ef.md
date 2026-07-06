### Title
RewardSupplier Token Balance Can Be Less Than `unclaimed_rewards`, Causing Temporary Freeze of Reward Claims - (File: src/reward_supplier/reward_supplier.cairo)

---

### Summary
`RewardSupplier.claim_rewards()` guards only against `amount > unclaimed_rewards` (an accounting variable), but never checks whether the contract's actual STRK token balance is sufficient. Because `unclaimed_rewards` is incremented immediately on every reward update while real tokens arrive from L1 asynchronously, the contract's balance can be less than the amount it attempts to transfer. Any call to claim staker or pool rewards during this window reverts, temporarily freezing unclaimed yield.

---

### Finding Description
In `src/reward_supplier/reward_supplier.cairo`, `claim_rewards` (lines 205–220) performs only an accounting guard:

```cairo
let unclaimed_rewards = self.unclaimed_rewards.read();
assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);

self.unclaimed_rewards.write(unclaimed_rewards - amount);
let token_dispatcher = self.token_dispatcher.read();
token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
``` [1](#0-0) 

There is no check that `token_dispatcher.balance_of(get_contract_address()) >= amount`.

`unclaimed_rewards` is incremented immediately inside `update_unclaimed_rewards_from_staking_contract` (lines 198–201):

```cairo
let unclaimed_rewards = self.unclaimed_rewards.read() + rewards;
self.unclaimed_rewards.write(unclaimed_rewards);
self.request_funds(:unclaimed_rewards);
``` [2](#0-1) 

`request_funds` (lines 301–331) then computes `credit = balance + l1_pending_requested_amount` and sends L1 mint messages only if `credit < debit + threshold`. Crucially, `l1_pending_requested_amount` counts tokens *requested but not yet received*. The actual on-chain balance can therefore be far below `unclaimed_rewards` while L1 messages are in flight. [3](#0-2) 

In `_update_rewards` (staking.cairo lines 2348–2360), the staking contract calls `update_unclaimed_rewards_from_staking_contract` and then *immediately* calls `claim_from_reward_supplier` in the same transaction:

```cairo
reward_supplier_dispatcher
    .update_unclaimed_rewards_from_staking_contract(
        rewards: staker_rewards + total_pools_rewards,
    );
// Claim pools rewards.
claim_from_reward_supplier(
    :reward_supplier_dispatcher,
    amount: total_pools_rewards,
    token_dispatcher: strk_token_dispatcher(),
);
``` [4](#0-3) 

The L1 mint messages dispatched by `request_funds` cannot be processed within the same L2 transaction. If the RewardSupplier's current balance is less than `total_pools_rewards`, `checked_transfer` reverts, rolling back the entire reward update.

The same revert path is hit when a staker calls `claim_rewards` on the staking contract, which calls `send_rewards_to_staker`, which calls `claim_from_reward_supplier`: [5](#0-4) 

---

### Impact Explanation
**High – Temporary freezing of unclaimed yield.**

When the RewardSupplier's STRK balance is below the amount being claimed (a normal transient state while L1 messages are in flight), every call to:
- `update_rewards_from_attestation_contract` / `update_rewards` (reward update path)
- `claim_rewards` on the staking contract (staker reward claim path)

reverts. Stakers and pool members are unable to receive their earned rewards for the duration of the funding gap. Rewards are not permanently lost, but they are inaccessible until L1 tokens arrive, constituting a temporary freeze of unclaimed yield.

---

### Likelihood Explanation
**Realistic in normal operation.** The L1→L2 bridge message delivery is asynchronous and can take minutes to hours. The `request_funds` mechanism only guarantees that *credit* (balance + pending L1 amount) eventually covers *debit* (unclaimed_rewards); it does not guarantee that the actual on-chain balance is sufficient at the moment of a claim. Any epoch where rewards are calculated and immediately claimed before the prior L1 mint messages are consumed will trigger this revert. This is not a contrived edge case — it is the steady-state operating condition of the protocol between L1 mint deliveries.

---

### Recommendation
Add an explicit balance check inside `RewardSupplier.claim_rewards` before attempting the transfer:

```cairo
fn claim_rewards(ref self: ContractState, amount: Amount) {
    let staking_contract = self.staking_contract.read();
    assert!(
        get_caller_address() == staking_contract,
        "{}",
        GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
    );
    let unclaimed_rewards = self.unclaimed_rewards.read();
    assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);

    // Analog of the recommended fix from the external report:
    let token_dispatcher = self.token_dispatcher.read();
    let balance: Amount = token_dispatcher
        .balance_of(account: get_contract_address())
        .try_into()
        .expect_with_err(InternalError::BALANCE_ISNT_AMOUNT_TYPE);
    assert!(balance >= amount, "RewardSupplier: Insufficient token balance");

    self.unclaimed_rewards.write(unclaimed_rewards - amount);
    token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
}
```

This surfaces a clear, actionable error instead of a generic ERC20 revert, and makes the invariant explicit. Additionally, consider decoupling the immediate `claim_from_reward_supplier` call in `_update_rewards` from the reward accounting update, so that pool reward transfers are deferred until the RewardSupplier balance is confirmed sufficient.

---

### Proof of Concept

1. Protocol is live; `RewardSupplier.unclaimed_rewards = 0`, `balance = 100 STRK`, `l1_pending_requested_amount = 0`.
2. Attestation occurs; `_update_rewards` is called for a staker with a pool. Suppose `total_pools_rewards = 150 STRK`.
3. `update_unclaimed_rewards_from_staking_contract(150)` → `unclaimed_rewards = 150`. `request_funds` fires an L1 mint message for the shortfall; `l1_pending_requested_amount` increases. L1 message is **not yet processed**.
4. `claim_from_reward_supplier(amount: 150)` is called in the same transaction. `assert!(150 <= 150)` passes. `checked_transfer(staking_contract, 150)` is attempted. Actual balance = 100 < 150 → **revert**.
5. The entire `_update_rewards` transaction reverts. The staker's rewards are not updated; pool members cannot claim. This repeats every epoch until the L1 mint message is consumed and the balance is replenished.

### Citations

**File:** src/reward_supplier/reward_supplier.cairo (L198-201)
```text
            let unclaimed_rewards = self.unclaimed_rewards.read() + rewards;
            self.unclaimed_rewards.write(unclaimed_rewards);
            // Request funds from L1 if needed.
            self.request_funds(:unclaimed_rewards);
```

**File:** src/reward_supplier/reward_supplier.cairo (L213-219)
```text
            let unclaimed_rewards = self.unclaimed_rewards.read();
            assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);

            // Update unclaimed_rewards and transfer the requested rewards to the staking contract.
            self.unclaimed_rewards.write(unclaimed_rewards - amount);
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
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

**File:** src/staking/staking.cairo (L1620-1626)
```text
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();
```

**File:** src/staking/staking.cairo (L2351-2360)
```text
            reward_supplier_dispatcher
                .update_unclaimed_rewards_from_staking_contract(
                    rewards: staker_rewards + total_pools_rewards,
                );
            // Claim pools rewards.
            claim_from_reward_supplier(
                :reward_supplier_dispatcher,
                amount: total_pools_rewards,
                token_dispatcher: strk_token_dispatcher(),
            );
```
