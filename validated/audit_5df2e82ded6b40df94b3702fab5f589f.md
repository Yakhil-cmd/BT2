### Title
Temporary Freezing of Unclaimed Yield Due to Accounting/Liquidity Mismatch in RewardSupplier - (File: src/reward_supplier/reward_supplier.cairo)

### Summary
The `RewardSupplier` contract tracks owed rewards in `unclaimed_rewards` (an accounting ledger) but the actual STRK token balance can be lower than `unclaimed_rewards` during the L1→L2 bridge delay window. The `claim_rewards` function only validates the accounting invariant (`amount <= unclaimed_rewards`) without verifying the actual token balance, causing `checked_transfer` to revert and temporarily freezing all staker and delegator yield claims.

### Finding Description
When rewards are distributed, `_update_rewards` in `staking.cairo` calls `reward_supplier_dispatcher.update_unclaimed_rewards_from_staking_contract(rewards)`, which increases `unclaimed_rewards` and calls `request_funds` to send L1 mint messages if the balance is insufficient. [1](#0-0) 

`request_funds` computes `credit = balance + l1_pending_requested_amount` and only sends L1 messages — it does **not** add actual tokens to the contract balance. The tokens arrive later via the StarkGate bridge. [2](#0-1) 

After `request_funds`, the invariant is `balance + l1_pending >= unclaimed_rewards + threshold`. When `l1_pending > threshold`, this means `balance < unclaimed_rewards`. During this window, `claim_rewards` passes the accounting check but the `checked_transfer` reverts: [3](#0-2) 

The staking contract's `claim_from_reward_supplier` wrapper also asserts the balance increased by the exact amount, so the entire transaction reverts: [4](#0-3) 

This affects both staker reward claims via `send_rewards_to_staker`: [5](#0-4) 

And pool reward distributions via `send_rewards_to_delegation_pool` (called from `update_pool_rewards`), which transfers STRK to the pool contract before `update_rewards_from_staking_contract` is called on the pool: [6](#0-5) 

### Impact Explanation
Any staker calling `claim_rewards` or `unstake_action`, and any delegator triggering `exit_delegation_pool_action`, will have their transaction revert with `INSUFFICIENT_BALANCE` during the bridge delay window. This constitutes **temporary freezing of unclaimed yield** — earned rewards are correctly accounted for but cannot be transferred until L1 mint messages are processed by StarkGate. The window can last hours to days depending on L1 congestion.

### Likelihood Explanation
This condition is reached in normal protocol operation: every epoch where rewards are distributed and the RewardSupplier's on-chain STRK balance is below `unclaimed_rewards` (i.e., `l1_pending_requested_amount > threshold`). This is the expected steady-state for a protocol that relies on L1 minting — the balance is routinely lower than the accounting ledger between mint cycles. Any staker or delegator who attempts to claim during this window triggers the freeze with no special privileges required.

### Recommendation
`claim_rewards` in `RewardSupplier` should verify the actual token balance before attempting the transfer and revert with a descriptive error (e.g., `INSUFFICIENT_LIQUIDITY_PENDING_L1_MINT`) rather than propagating an opaque ERC-20 transfer failure. Additionally, consider adding a view function that exposes whether the contract has sufficient balance to service a given claim amount, so callers can check before transacting.

### Proof of Concept
1. Protocol starts with `balance = 0`, `unclaimed_rewards = 0`, `l1_pending = 0`.
2. Staker attests → `_update_rewards` accrues `R` STRK rewards → `update_unclaimed_rewards_from_staking_contract(R)` is called → `unclaimed_rewards = R`.
3. `request_funds` fires: `credit = 0 + 0 = 0 < R + threshold` → sends L1 mint messages → `l1_pending = ceil((R+threshold)/base_mint_amount) * base_mint_amount`. Balance remains `0`.
4. Before the StarkGate bridge processes the L1 message, staker calls `staking.claim_rewards(staker_address)`.
5. Flow: `send_rewards_to_staker` → `claim_from_reward_supplier(amount=R)` → `reward_supplier.claim_rewards(R)`.
6. Check `R <= unclaimed_rewards` (= R) passes. Then `checked_transfer(staking_contract, R)` reverts with `INSUFFICIENT_BALANCE` because the RewardSupplier holds 0 STRK.
7. The entire `claim_rewards` transaction reverts. The staker's earned yield is frozen until the L1 bridge delivers tokens. [7](#0-6) [8](#0-7)

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

**File:** src/staking/staking.cairo (L1865-1891)
```text
        fn update_pool_rewards(
            ref self: ContractState,
            staker_address: ContractAddress,
            pools_rewards_data: Array<(ContractAddress, ContractAddress, NormalizedAmount, Amount)>,
        ) -> Array<(ContractAddress, Amount)> {
            let mut pool_rewards_list = array![];
            let strk_token_dispatcher = strk_token_dispatcher();
            for (pool_contract, token_address, pool_balance, pool_rewards) in pools_rewards_data {
                let pool_dispatcher = IPoolDispatcher { contract_address: pool_contract };
                // Rewards are always in STRK.
                self
                    .send_rewards_to_delegation_pool(
                        :staker_address,
                        pool_address: pool_contract,
                        amount: pool_rewards,
                        token_dispatcher: strk_token_dispatcher,
                    );
                let decimals = self.get_token_decimals(:token_address);
                pool_dispatcher
                    .update_rewards_from_staking_contract(
                        rewards: pool_rewards,
                        pool_balance: pool_balance.to_native_amount(:decimals),
                    );
                pool_rewards_list.append((pool_contract, pool_rewards));
            }
            pool_rewards_list
        }
```
