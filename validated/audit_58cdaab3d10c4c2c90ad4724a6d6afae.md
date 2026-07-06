### Title
`RewardSupplier.claim_rewards()` May Revert Due to Insufficient Token Balance While `unclaimed_rewards` Accounting Shows Funds Available - (File: `src/reward_supplier/reward_supplier.cairo`)

### Summary

The `RewardSupplier` contract maintains an internal accounting variable `unclaimed_rewards` that tracks how much STRK is owed to the staking contract. However, the actual token balance of the contract can be lower than `unclaimed_rewards` because tokens are requested from L1 asynchronously via the bridge. When a staker or pool member calls `claim_rewards`, the call chain reaches `RewardSupplier.claim_rewards()`, which validates only `amount <= unclaimed_rewards` before attempting a token transfer. If the actual on-chain balance is insufficient (tokens still in transit from L1), the `checked_transfer` reverts, freezing all reward claims until the bridge delivers the tokens.

### Finding Description

The `RewardSupplier` contract uses two variables to track its financial state:

- `unclaimed_rewards`: accounting variable incremented every time the staking contract reports new rewards
- `l1_pending_requested_amount`: amount already requested from L1 but not yet received

The `request_funds` internal function maintains the invariant:

```
balance + l1_pending_requested_amount >= unclaimed_rewards + threshold
``` [1](#0-0) 

This invariant explicitly allows `balance = 0` as long as `l1_pending_requested_amount >= unclaimed_rewards + threshold`. In other words, the contract is designed to operate with zero actual token balance while relying on in-transit L1 funds.

When `claim_rewards(amount)` is called, the only guard is:

```cairo
assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);
``` [2](#0-1) 

There is no check that `amount <= actual_token_balance`. The subsequent `checked_transfer` will revert if the contract's real balance is insufficient.

The call chain from an unprivileged staker is:

1. `Staking.claim_rewards(staker_address)` → `send_rewards_to_staker()`
2. → `claim_from_reward_supplier(reward_supplier_dispatcher, amount, token_dispatcher)`
3. → `reward_supplier_dispatcher.claim_rewards(amount)` → `checked_transfer` **reverts** [3](#0-2) [4](#0-3) 

The same freeze applies to pool rewards: during `_update_rewards`, `claim_from_reward_supplier` is called immediately for `total_pools_rewards` before transferring to pool contracts. [5](#0-4) 

### Impact Explanation

Any staker or pool member who has accrued `unclaimed_rewards_own > 0` will be unable to call `claim_rewards` for the duration of the L1→L2 bridge delay (typically hours to days). This constitutes a **temporary freeze of unclaimed yield**. The staker has no mechanism to force the bridge to deliver faster, and the protocol provides no fallback path to claim rewards from a different source.

This matches the allowed impact: **High: Temporary freezing of unclaimed yield or unclaimed royalties**.

### Likelihood Explanation

This is a **normal operating condition**, not an edge case. The `request_funds` logic is explicitly designed to allow `balance = 0` while relying on `l1_pending_requested_amount` to cover obligations. Every epoch in which rewards are distributed and the reward supplier's balance has been depleted (transferred to the staking contract for pool rewards) will produce a window where `balance < unclaimed_rewards`. Any staker who calls `claim_rewards` during this window will be reverted.

### Recommendation

In `RewardSupplier.claim_rewards()`, add a check that the actual token balance is sufficient before attempting the transfer:

```cairo
let balance: Amount = token_dispatcher
    .balance_of(account: get_contract_address())
    .try_into()
    .expect_with_err(InternalError::BALANCE_ISNT_AMOUNT_TYPE);
assert!(amount <= balance, "{}", Error::INSUFFICIENT_BALANCE);
```

Alternatively, the staking contract's `send_rewards_to_staker` and `_update_rewards` should gracefully handle the case where the reward supplier cannot immediately fulfill the claim (e.g., by deferring the transfer and allowing a retry once the bridge delivers funds).

### Proof of Concept

1. The reward supplier starts with `balance = 0`, `l1_pending = B`, `unclaimed_rewards = B - threshold` (invariant holds: `0 + B >= B - threshold + threshold`).
2. The staking contract calls `update_unclaimed_rewards_from_staking_contract(R)` for a new epoch's rewards. `unclaimed_rewards` becomes `B - threshold + R`. `request_funds` sends another L1 message; `l1_pending` increases but `balance` remains `0`.
3. Staker calls `Staking.claim_rewards(staker_address)` for their accrued `R_own <= R`.
4. `send_rewards_to_staker` → `claim_from_reward_supplier(amount = R_own)` → `reward_supplier.claim_rewards(R_own)`.
5. Check `R_own <= unclaimed_rewards` passes.
6. `token_dispatcher.checked_transfer(staking_contract, R_own)` reverts because `balance = 0 < R_own`.
7. The entire transaction reverts. The staker's earned rewards are frozen until the L1 bridge delivers tokens. [6](#0-5)

### Citations

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

**File:** src/staking/utils.cairo (L50-59)
```text
pub(crate) fn claim_from_reward_supplier(
    reward_supplier_dispatcher: IRewardSupplierDispatcher,
    amount: Amount,
    token_dispatcher: IERC20Dispatcher,
) {
    let staking_contract = get_contract_address();
    let balance_before = token_dispatcher.balance_of(account: staking_contract);
    reward_supplier_dispatcher.claim_rewards(:amount);
    let balance_after = token_dispatcher.balance_of(account: staking_contract);
    assert!(balance_after - balance_before == amount.into(), "{}", Error::UNEXPECTED_BALANCE);
```

**File:** src/staking/staking.cairo (L1620-1628)
```text
            let reward_address = staker_info.reward_address;
            let amount = staker_info.unclaimed_rewards_own;
            let reward_supplier_dispatcher = self.reward_supplier_dispatcher.read();

            claim_from_reward_supplier(:reward_supplier_dispatcher, :amount, :token_dispatcher);
            token_dispatcher.checked_transfer(recipient: reward_address, amount: amount.into());
            staker_info.unclaimed_rewards_own = Zero::zero();

            self.emit(Events::StakerRewardClaimed { staker_address, reward_address, amount });
```

**File:** src/staking/staking.cairo (L2355-2365)
```text
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
