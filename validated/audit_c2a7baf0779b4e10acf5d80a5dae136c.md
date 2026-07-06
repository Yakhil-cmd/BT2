### Title
RewardSupplier `claim_rewards` Does Not Check Actual Token Balance Before Transfer, Causing Temporary Freezing of Unclaimed Yield - (File: `src/reward_supplier/reward_supplier.cairo`)

---

### Summary

The `RewardSupplier.claim_rewards` function validates only that `unclaimed_rewards >= amount` but never checks whether the contract's actual STRK token balance is sufficient to cover the transfer. Because `unclaimed_rewards` is an accounting variable that is incremented immediately while the corresponding L1 mint funds arrive asynchronously via StarkGate, the actual balance can be lower than `unclaimed_rewards` during the cross-chain delay window. When `_update_rewards` calls `update_unclaimed_rewards_from_staking_contract` (which increments `unclaimed_rewards` and fires async L1 mint requests) and then immediately calls `claim_from_reward_supplier` for pool rewards in the same transaction, the `checked_transfer` inside `claim_rewards` will revert if the actual balance is insufficient. This causes the entire `update_rewards` / `update_rewards_from_attestation_contract` transaction to revert, temporarily freezing reward distribution for all stakers and delegators.

---

### Finding Description

**Root cause — `RewardSupplier.claim_rewards` (reward_supplier.cairo:205–220):**

```cairo
fn claim_rewards(ref self: ContractState, amount: Amount) {
    ...
    let unclaimed_rewards = self.unclaimed_rewards.read();
    assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);  // accounting check only

    self.unclaimed_rewards.write(unclaimed_rewards - amount);
    let token_dispatcher = self.token_dispatcher.read();
    token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
    // ^^^ will revert if actual balance < amount, even though unclaimed_rewards >= amount
}
``` [1](#0-0) 

The only guard is `amount <= unclaimed_rewards`. There is no `balance >= amount` check. `unclaimed_rewards` is an accounting counter that can exceed the actual token balance whenever L1 mint funds are in transit.

**How `unclaimed_rewards` diverges from actual balance:**

`update_unclaimed_rewards_from_staking_contract` increments `unclaimed_rewards` and calls `request_funds`, which sends async L1 messages to mint tokens. The tokens do not arrive until the L1 `tick()` is processed and StarkGate bridges them back to L2. [2](#0-1) 

`request_funds` counts `l1_pending_requested_amount` as "credit" even though those tokens have not yet arrived: [3](#0-2) 

**The vulnerable call sequence in `_update_rewards` (staking.cairo:2348–2360):**

```
1. update_unclaimed_rewards_from_staking_contract(staker_rewards + pool_rewards)
   → unclaimed_rewards += (staker_rewards + pool_rewards)
   → request_funds() sends L1 mint messages (async, tokens NOT yet on L2)

2. claim_from_reward_supplier(pool_rewards)          ← same transaction, same block
   → reward_supplier.claim_rewards(pool_rewards)
   → assert pool_rewards <= unclaimed_rewards  ✓ (passes, we just incremented it)
   → checked_transfer(pool_rewards)            ✗ REVERTS if balance < pool_rewards
``` [4](#0-3) 

`claim_from_reward_supplier` in `utils.cairo` also asserts the balance increased by exactly `amount`, but this assertion is never reached because `checked_transfer` reverts first: [5](#0-4) 

The reward supplier is initialized with only `STRK_IN_FRIS` (1 STRK) as its starting balance: [6](#0-5) 

---

### Impact Explanation

When the reward supplier's actual STRK balance is less than `total_pools_rewards` for a given `update_rewards` call, the entire transaction reverts. This means:

- `update_rewards` (called by the sequencer) cannot execute → no consensus rewards are distributed.
- `update_rewards_from_attestation_contract` (called by the attestation contract) cannot execute → no attestation rewards are distributed.
- All stakers and delegators are unable to accumulate or claim yield until the L1 mint funds arrive and the balance is replenished.

This constitutes **temporary freezing of unclaimed yield**, which is within the allowed impact scope.

---

### Likelihood Explanation

The cross-chain L1→L2 delay via StarkGate is inherent to the design. The window during which `unclaimed_rewards > actual_balance` is not a corner case — it is the normal operating state between when rewards are computed and when L1 mint funds arrive. Concretely:

1. The reward supplier starts with only 1 STRK balance. Any epoch where pool rewards exceed 1 STRK triggers the revert on the very first `update_rewards` call.
2. Even after the initial funding, every epoch where cumulative new rewards exceed the remaining balance before the next L1 mint delivery will cause the same revert.
3. The `request_funds` threshold mechanism counts `l1_pending_requested_amount` as available credit, masking the true deficit from the accounting check while the actual balance remains insufficient.

---

### Recommendation

Add an explicit balance check inside `claim_rewards` before attempting the transfer, or restructure `_update_rewards` so that pool rewards are only claimed after confirming the reward supplier holds sufficient actual balance:

```cairo
fn claim_rewards(ref self: ContractState, amount: Amount) {
    ...
    let unclaimed_rewards = self.unclaimed_rewards.read();
    assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);

    // Add: verify actual token balance is sufficient
    let balance: Amount = token_dispatcher
        .balance_of(account: get_contract_address())
        .try_into()
        .expect_with_err(InternalError::BALANCE_ISNT_AMOUNT_TYPE);
    assert!(amount <= balance, "{}", Error::INSUFFICIENT_BALANCE_FOR_CLAIM);

    self.unclaimed_rewards.write(unclaimed_rewards - amount);
    token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
}
```

Alternatively, `_update_rewards` should defer the pool reward transfer to a separate transaction or only transfer up to the available balance, deferring the remainder.

---

### Proof of Concept

The following sequence demonstrates the revert path:

1. Deploy the system. Reward supplier has `balance = 1 STRK`, `unclaimed_rewards = 1 STRK`.
2. A staker with a large delegation pool stakes. After K epochs, `update_rewards` is called.
3. Suppose `total_pools_rewards = 5 STRK` for this block.
4. `update_unclaimed_rewards_from_staking_contract(staker_rewards + 5 STRK)` executes:
   - `unclaimed_rewards` becomes `1 + staker_rewards + 5 STRK`
   - `request_funds` sends L1 mint messages (tokens not yet on L2)
5. `claim_from_reward_supplier(5 STRK)` executes:
   - `reward_supplier.claim_rewards(5 STRK)` checks `5 <= unclaimed_rewards` → passes
   - `checked_transfer(staking_contract, 5 STRK)` → **REVERTS** because actual balance is 1 STRK
6. Entire `update_rewards` transaction reverts. No rewards are distributed. The sequencer cannot advance reward state until L1 funds arrive. [7](#0-6) [8](#0-7)

### Citations

**File:** src/reward_supplier/reward_supplier.cairo (L125-128)
```text
        // Initialize unclaimed_rewards with 1 STRK to make up for round ups of pool rewards
        // calculation in the staking contract.
        self.unclaimed_rewards.write(STRK_IN_FRIS);
        self.l1_pending_requested_amount.write(Zero::zero());
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

**File:** src/staking/staking.cairo (L2313-2376)
```text
        fn _update_rewards(
            ref self: ContractState,
            staker_address: ContractAddress,
            strk_total_rewards: Amount,
            btc_total_rewards: Amount,
            strk_total_stake: NormalizedAmount,
            btc_total_stake: NormalizedAmount,
            mut staker_info: InternalStakerInfoLatest,
            staker_pool_info: StoragePath<InternalStakerPoolInfoV2>,
            reward_supplier_dispatcher: IRewardSupplierDispatcher,
            curr_epoch: Epoch,
        ) {
            // Calculate self rewards.
            let staker_own_rewards = self
                .calculate_staker_own_rewards(
                    :staker_address, :strk_total_rewards, :strk_total_stake, :curr_epoch,
                );

            // Calculate pools rewards.
            let (commission_rewards, total_pools_rewards, pools_rewards_data) = if staker_pool_info
                .has_pool() {
                self
                    .calculate_staker_pools_rewards(
                        :staker_address,
                        :staker_pool_info,
                        :strk_total_rewards,
                        :strk_total_stake,
                        :btc_total_rewards,
                        :btc_total_stake,
                        :curr_epoch,
                    )
            } else {
                (Zero::zero(), Zero::zero(), array![])
            };

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
            // Emit event.
            self
                .emit(
                    Events::StakerRewardsUpdated {
                        staker_address, staker_rewards, pool_rewards: pool_rewards_list.span(),
                    },
                );

            // Write staker rewards to storage.
            self.write_staker_info(:staker_address, :staker_info);
        }
```

**File:** src/staking/utils.cairo (L50-60)
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
}
```
