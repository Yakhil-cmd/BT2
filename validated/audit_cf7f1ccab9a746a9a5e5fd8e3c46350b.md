### Title
Reward Supplier Actual Token Balance Can Be Insufficient to Pay Out Registered Rewards, Temporarily Freezing Staker/Delegator Withdrawals — (File: `src/reward_supplier/reward_supplier.cairo`)

---

### Summary

The `RewardSupplier` contract tracks owed rewards via an accounting variable `unclaimed_rewards`, but the `request_funds` mechanism counts L1-pending (not-yet-arrived) amounts as available "credit." This creates a window where `unclaimed_rewards >= amount` (accounting check passes) but the actual on-chain token balance is zero or insufficient. Any call to `claim_rewards` in the reward supplier then reverts at `checked_transfer`, blocking stakers from claiming yield and blocking `unstake_action` from returning principal.

---

### Finding Description

**Reward registration and fund request flow** (`reward_supplier.cairo` lines 189–201):

```cairo
fn update_unclaimed_rewards_from_staking_contract(ref self: ContractState, rewards: Amount) {
    let unclaimed_rewards = self.unclaimed_rewards.read() + rewards;
    self.unclaimed_rewards.write(unclaimed_rewards);
    self.request_funds(:unclaimed_rewards);   // <-- may NOT send new L1 request
}
```

`request_funds` (lines 301–331) computes:

```cairo
let credit = balance + l1_pending_requested_amount;   // includes undelivered L1 funds
let debit  = unclaimed_rewards;
if credit < debit + threshold { /* send L1 message */ }
```

If `l1_pending_requested_amount` is already large enough to satisfy `debit + threshold`, no new L1 message is sent. The actual on-chain `balance` can be **zero** while `credit` appears sufficient.

**Claim path** (lines 205–219):

```cairo
fn claim_rewards(ref self: ContractState, amount: Amount) {
    let unclaimed_rewards = self.unclaimed_rewards.read();
    assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);  // passes
    self.unclaimed_rewards.write(unclaimed_rewards - amount);
    token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
    // ^^^ REVERTS with INSUFFICIENT_BALANCE if actual balance < amount
}
```

The accounting assertion passes, but `checked_transfer` reverts because the actual token balance is zero (L1 funds are still in transit).

**Propagation to staker/delegator exits:**

`send_rewards_to_staker` (staking.cairo lines 1614–1628) calls `claim_from_reward_supplier` before transferring rewards to the staker's reward address. If `claim_from_reward_supplier` reverts, the entire call reverts:

- `staking::claim_rewards` → `send_rewards_to_staker` → `claim_from_reward_supplier` → **revert**
- `staking::unstake_action` → `send_rewards_to_staker` → `claim_from_reward_supplier` → **revert** (principal also locked)

Additionally, `_update_rewards` (staking.cairo lines 2351–2360) immediately calls `claim_from_reward_supplier(total_pools_rewards)` right after registering rewards. If the balance is zero, this reverts, blocking the attestation reward update entirely.

---

### Impact Explanation

- **Temporary freezing of unclaimed yield**: Stakers and delegators cannot call `claim_rewards` until L1 bridge funds arrive.
- **Temporary freezing of principal**: `unstake_action` reverts because it calls `send_rewards_to_staker` before returning the staked principal. A staker who has already passed the exit wait window cannot retrieve their tokens.
- **Attestation reward update blocked**: `_update_rewards` reverts if pool rewards cannot be immediately claimed from the reward supplier, stalling the entire per-block reward distribution.

This matches the allowed impact: **High — Temporary freezing of funds / Temporary freezing of unclaimed yield**.

---

### Likelihood Explanation

The L1→L2 bridge has an inherent multi-hour delivery delay. The reward supplier starts with a finite initial balance. As attestations accumulate rewards, the balance is drawn down. `request_funds` sends L1 messages reactively (after rewards are registered), not proactively. During the delivery window — which can span many blocks — any `claim_rewards` or `unstake_action` call will revert. This is a normal operating condition, not an edge case.

---

### Recommendation

1. In `claim_rewards` (reward supplier), check the actual token balance before asserting `unclaimed_rewards >= amount`, and revert with a descriptive error if the balance is insufficient, so callers can retry later without corrupting accounting state.
2. In `_update_rewards`, decouple the immediate pool-reward transfer from the reward registration step, or make the pool-reward claim non-reverting (e.g., defer it to a separate call).
3. Consider maintaining a minimum on-chain liquidity buffer that is replenished before `unclaimed_rewards` can grow beyond it, rather than relying solely on `l1_pending_requested_amount` as virtual credit.

---

### Proof of Concept

1. Reward supplier is deployed with `balance = 0`, `l1_pending_requested_amount = T` (a prior request is in flight), `unclaimed_rewards = 0`.
2. A staker attests. `_update_rewards` calls `update_unclaimed_rewards_from_staking_contract(R)`.
   - `unclaimed_rewards` becomes `R`.
   - `request_funds(R)`: `credit = 0 + T`. If `T >= R + threshold`, no new L1 message is sent.
3. `_update_rewards` immediately calls `claim_from_reward_supplier(pool_rewards)`.
   - `reward_supplier.claim_rewards(pool_rewards)`: accounting check passes (`pool_rewards <= R`).
   - `checked_transfer(pool_rewards)` → **reverts** with `INSUFFICIENT_BALANCE` because actual balance is 0.
4. The entire attestation transaction reverts.
5. Separately, any staker calling `staking::claim_rewards` or `staking::unstake_action` also reverts for the same reason until the L1 bridge delivers the pending funds. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5)

### Citations

**File:** src/reward_supplier/reward_supplier.cairo (L189-202)
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
