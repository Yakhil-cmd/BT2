### Title
`unstake_action` Reverts When Reward Supplier Has Insufficient Token Balance, Temporarily Freezing Staker Principal — (File: `src/staking/staking.cairo`)

---

### Summary

`unstake_action` atomically bundles reward distribution with principal return. If the `RewardSupplier` contract's actual STRK token balance is less than the staker's `unclaimed_rewards_own` — a condition that arises during the L1→L2 bridge latency window — the entire `unstake_action` call reverts. The staker cannot withdraw their principal stake even after the exit wait window has elapsed, and has no alternative exit path.

---

### Finding Description

In `unstake_action`, the first substantive operation is a call to `send_rewards_to_staker`:

```cairo
// staking.cairo:495
self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
```

`send_rewards_to_staker` (staking.cairo:1614–1629) calls `claim_from_reward_supplier` with `amount = staker_info.unclaimed_rewards_own`, then transfers that amount to the reward address:

```cairo
claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
```

`claim_from_reward_supplier` calls `reward_supplier.claim_rewards(amount)` (reward_supplier.cairo:205–220):

```cairo
let unclaimed_rewards = self.unclaimed_rewards.read();
assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);
self.unclaimed_rewards.write(unclaimed_rewards - amount);
let token_dispatcher = self.token_dispatcher.read();
token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
```

The accounting check (`amount <= unclaimed_rewards`) can pass while the reward supplier's **actual STRK token balance** is less than `amount`. This is because `request_funds` (reward_supplier.cairo:301–331) counts `l1_pending_requested_amount` as credit:

```cairo
let credit = balance + l1_pending_requested_amount;
let debit = unclaimed_rewards;
if credit < debit + threshold {
    // send L1 mint request
}
```

The system guarantees `balance + l1_pending_requested_amount >= unclaimed_rewards + threshold`, but `balance` alone can be less than `unclaimed_rewards` during the L1 bridge latency window. When `checked_transfer` is called with `amount > balance`, it reverts, causing the entire `unstake_action` to revert.

The staker has no alternative exit path: `claim_rewards` (staking.cairo:411–431) also calls `send_rewards_to_staker` and fails for the same reason. There is no way to zero out `unclaimed_rewards_own` without going through the reward supplier.

---

### Impact Explanation

The staker's principal stake — held in the staking contract — cannot be withdrawn because `unstake_action` requires reward distribution to succeed first. Since `claim_rewards` also fails under the same condition, the staker has no mechanism to clear their unclaimed rewards and retry. This constitutes **temporary freezing of the staker's principal funds** until the L1 bridge delivers the pending tokens.

---

### Likelihood Explanation

The `RewardSupplier` relies on L1→L2 bridge delivery to maintain sufficient token balance. The bridge has inherent latency (hours to days on Ethereum). During this window, any staker with non-zero `unclaimed_rewards_own` who calls `unstake_action` will have their transaction revert. This is a realistic scenario for any active staker who has accumulated rewards, and the window can be prolonged if reward accrual outpaces bridge delivery.

---

### Recommendation

Decouple reward distribution from principal return in `unstake_action`. If the reward supplier is temporarily underfunded, allow `unstake_action` to succeed without transferring rewards, preserving `unclaimed_rewards_own` for a later `claim_rewards` call once the supplier is funded. This mirrors the RocketPool fix: continue the critical state transition (exit) regardless of whether the ancillary payment (rewards) can be completed immediately.

---

### Proof of Concept

1. Staker stakes and accumulates `unclaimed_rewards_own = R > 0`.
2. `_update_rewards` calls `update_unclaimed_rewards_from_staking_contract(rewards: R)`, increasing `unclaimed_rewards` in the reward supplier.
3. `request_funds` sends an L1 mint request; `l1_pending_requested_amount` increases but actual `balance` remains `< R` (bridge latency).
4. Staker calls `unstake_intent()` — succeeds.
5. Exit wait window elapses.
6. Staker calls `unstake_action(staker_address)`.
7. `send_rewards_to_staker` → `claim_from_reward_supplier(amount: R)` → `reward_supplier.claim_rewards(R)`.
8. Accounting check: `R <= unclaimed_rewards` ✓ (passes).
9. `checked_transfer(recipient: staking_contract, amount: R)` — **REVERTS** because `balance < R`.
10. Entire `unstake_action` reverts; staker's principal remains locked in the staking contract. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** src/staking/staking.cairo (L483-515)
```text
        fn unstake_action(ref self: ContractState, staker_address: ContractAddress) -> Amount {
            // Prerequisites and asserts.
            self.general_prerequisites();
            let mut staker_info = self.internal_staker_info(:staker_address);
            let unstake_time = staker_info
                .unstake_time
                .expect_with_err(Error::MISSING_UNSTAKE_INTENT);
            assert!(Time::now() >= unstake_time, "{}", GenericError::INTENT_WINDOW_NOT_FINISHED);

            // Send rewards to staker's reward address.
            // It must be part of this function's flow because staker_info is about to be erased.
            let token_dispatcher = strk_token_dispatcher();
            self.send_rewards_to_staker(:staker_address, ref :staker_info, :token_dispatcher);
            // Update staker info to storage (it will be erased later).
            // This is done here to avoid re-entrancy.
            self.write_staker_info(:staker_address, :staker_info);

            let staker_amount = self.get_own_balance(:staker_address).to_strk_native_amount();
            let staker_pool_info = self.staker_pool_info.entry(staker_address);
            self.remove_staker(:staker_address, :staker_info, :staker_pool_info);

            // Return stake to staker.
            token_dispatcher
                .checked_transfer(recipient: staker_address, amount: staker_amount.into());
            // Return delegated stake to pools and zero their balances.
            self
                .transfer_to_pools_when_unstake(
                    :staker_address, staker_pool_info: staker_pool_info.as_non_mut(),
                );
            // Clear staker pools.
            staker_pool_info.pools.clear();
            staker_amount
        }
```

**File:** src/staking/staking.cairo (L1614-1629)
```text
        fn send_rewards_to_staker(
            ref self: ContractState,
            staker_address: ContractAddress,
            ref staker_info: InternalStakerInfoLatest,
            token_dispatcher: IERC20Dispatcher,
        ) {
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();

            self.emit(Events::StakerRewardClaimed { staker_address, reward_address, amount });
        }
```

**File:** src/reward_supplier/reward_supplier.cairo (L205-220)
```text
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
