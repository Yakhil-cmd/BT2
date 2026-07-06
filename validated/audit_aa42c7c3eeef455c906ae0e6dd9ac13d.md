### Title
Unclaimed Rewards Counter Can Exceed Actual Token Balance, Temporarily Freezing Reward Claims — (File: `src/reward_supplier/reward_supplier.cairo`)

---

### Summary

The `RewardSupplier` contract's `unclaimed_rewards` accounting counter is incremented whenever rewards are calculated, but the actual STRK token balance only increases when L1 funds arrive asynchronously via `on_receive()`. The `claim_rewards()` function validates only `amount <= unclaimed_rewards` — not `amount <= actual_balance` — so any reward claim attempted during the L1→L2 bridging window will revert at the `checked_transfer` step, temporarily freezing all unclaimed yield.

---

### Finding Description

**Step 1 — Rewards are promised before funds arrive.**

In `_update_rewards()` (staking.cairo), the staking contract calls:

```cairo
reward_supplier_dispatcher
    .update_unclaimed_rewards_from_staking_contract(
        rewards: staker_rewards + total_pools_rewards,
    );
``` [1](#0-0) 

Inside `update_unclaimed_rewards_from_staking_contract()`, `unclaimed_rewards` is incremented and `request_funds()` is called:

```cairo
let unclaimed_rewards = self.unclaimed_rewards.read() + rewards;
self.unclaimed_rewards.write(unclaimed_rewards);
self.request_funds(:unclaimed_rewards);
``` [2](#0-1) 

**Step 2 — `request_funds` counts pending L1 amounts as credit, not actual balance.**

`request_funds()` computes:

```cairo
let credit = balance + l1_pending_requested_amount;
let debit = unclaimed_rewards;
if credit < debit + threshold {
    // send L1 mint request messages
}
``` [3](#0-2) 

`l1_pending_requested_amount` is the amount already requested from L1 but **not yet received**. The function treats it as available credit, so the actual on-chain token balance can be far below `unclaimed_rewards` while the system considers itself solvent.

**Step 3 — `claim_rewards()` checks the counter, not the balance.**

```cairo
let unclaimed_rewards = self.unclaimed_rewards.read();
assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);

self.unclaimed_rewards.write(unclaimed_rewards - amount);
let token_dispatcher = self.token_dispatcher.read();
token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
``` [4](#0-3) 

The `assert!` on line 214 passes whenever `amount <= unclaimed_rewards`, but `checked_transfer` on line 219 requires the actual token balance to be sufficient. If `balance < amount`, the transfer reverts and the entire claim transaction fails.

**Step 4 — Pool rewards are claimed immediately inside `_update_rewards`, compounding the risk.**

Immediately after incrementing `unclaimed_rewards`, the staking contract calls:

```cairo
claim_from_reward_supplier(
    :reward_supplier_dispatcher,
    amount: total_pools_rewards,
    token_dispatcher: strk_token_dispatcher(),
);
``` [5](#0-4) 

If the actual balance is insufficient to cover `total_pools_rewards` at this point, the attestation-triggered reward update itself reverts — blocking not just claims but the entire reward-update flow for that epoch.

---

### Impact Explanation

- **Stakers and delegators see non-zero `unclaimed_rewards_own` / `pool_member_info.unclaimed_rewards`** (the accounting counter is correct), but every attempt to call `claim_rewards` reverts until L1 funds arrive.
- **Attestation-triggered reward updates can also revert** if the balance is insufficient to cover the immediate pool-rewards transfer inside `_update_rewards`, blocking the epoch reward cycle entirely.
- Impact classification: **High — Temporary freezing of unclaimed yield / temporary freezing of funds.**

---

### Likelihood Explanation

This is the **normal operating state** of the contract. Every attestation or `update_rewards` call increases `unclaimed_rewards` and sends an L1 mint request. L1→L2 message processing on Starknet takes hours to days. During that entire window, `unclaimed_rewards > actual_balance`. The window is not a rare edge case; it is the steady-state between every reward update and the corresponding L1 deposit. Any staker or delegator who claims rewards in this window — which is the common case — will have their transaction revert.

---

### Recommendation

1. In `claim_rewards()`, add a balance check before the transfer:
   ```cairo
   let balance = token_dispatcher.balance_of(account: get_contract_address());
   assert!(amount.into() <= balance, "{}", Error::INSUFFICIENT_BALANCE);
   ```
2. Alternatively, document clearly in user-facing interfaces that reward claims may temporarily revert while L1 funds are in transit, and surface the `l1_pending_requested_amount` field prominently so users understand the delay.
3. Consider a pull-based design where pool rewards are not transferred immediately inside `_update_rewards` but are instead credited to a pool-side counter, decoupling reward accounting from the L1 bridging latency.

---

### Proof of Concept

1. Staker's operational address calls `attest()` on the Attestation contract.
2. Attestation contract calls `update_rewards_from_attestation_contract(staker_address)` on the Staking contract.
3. Staking contract calls `_update_rewards(...)`, which calls `update_unclaimed_rewards_from_staking_contract(R)` — `unclaimed_rewards` becomes `R`, `request_funds` sends an L1 mint message, `l1_pending_requested_amount` becomes `R + threshold`. Actual balance remains `0` (or below `R`).
4. `_update_rewards` then calls `claim_from_reward_supplier(pool_rewards)` → `reward_supplier.claim_rewards(pool_rewards)` → `assert!(pool_rewards <= R)` passes → `checked_transfer(pool_rewards)` **reverts** because `balance = 0`.
5. Alternatively, if pool rewards are zero (staker-only), step 4 succeeds, but when the staker later calls `staking.claim_rewards(staker_address)` → `claim_from_reward_supplier(staker_rewards)` → same revert path.
6. The revert persists until the L1 mint message is processed and `on_receive()` is called by StarkGate, which can take hours to days. [6](#0-5) [7](#0-6) [8](#0-7)

### Citations

**File:** src/staking/staking.cairo (L2348-2365)
```text
            // Update reward supplier.
            let staker_rewards = staker_own_rewards + commission_rewards;
            // Update total rewards.
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
            // Update staker rewards.
            staker_info.unclaimed_rewards_own += staker_rewards;

            // Update pools rewards.
            let pool_rewards_list = self.update_pool_rewards(:staker_address, :pools_rewards_data);
```

**File:** src/reward_supplier/reward_supplier.cairo (L189-220)
```text
        fn update_unclaimed_rewards_from_staking_contract(
            ref self: ContractState, rewards: Amount,
        ) {
            assert!(
                get_caller_address() == self.staking_contract.read(),
                "{}",
                GenericError::CALLER_IS_NOT_STAKING_CONTRACT,
            );

            let unclaimed_rewards = self.unclaimed_rewards.read() + rewards;
            self.unclaimed_rewards.write(unclaimed_rewards);
            // Request funds from L1 if needed.
            self.request_funds(:unclaimed_rewards);
        }

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
