### Title
Balance Inflation Suppresses L1 Mint Requests, Causing Temporary Freeze of Unclaimed Yield — (File: src/reward_supplier/reward_supplier.cairo)

### Summary
The `request_funds` internal function in `RewardSupplier` uses a live `balance_of(get_contract_address())` call to compute available credit before deciding whether to send an L1 mint request. An unprivileged attacker can directly transfer STRK tokens to the `RewardSupplier` contract, artificially inflating the on-chain balance. This inflated balance causes `request_funds` to conclude that sufficient credit exists and skip the L1 mint request. When the inflated tokens are subsequently consumed by legitimate `claim_rewards` calls, the contract's actual balance falls below `unclaimed_rewards`, causing `checked_transfer` inside `claim_rewards` to revert and temporarily freezing staker reward withdrawals.

### Finding Description

The `request_funds` function computes a `credit` value as:

```
credit = balance_of(reward_supplier_contract) + l1_pending_requested_amount
```

and only sends an L1 mint request when `credit < unclaimed_rewards + threshold`. [1](#0-0) 

The `balance_of` call at line 304–307 reads the live ERC-20 balance of the contract, which any external actor can inflate by calling `STRK.transfer(reward_supplier_address, amount)` directly — no special privilege is required on Starknet. [2](#0-1) 

Crucially, a direct ERC-20 transfer does **not** trigger `on_receive`, so `l1_pending_requested_amount` is not updated to reflect the extra tokens. The inflated balance is therefore treated as genuine protocol-owned credit. [3](#0-2) 

When `claim_rewards` is later called by the staking contract, it performs a `checked_transfer` for the full `unclaimed_rewards` amount. If the inflated tokens have already been consumed by prior claims and no L1 mint was requested in time, the transfer reverts. [4](#0-3) 

There is no `farm`/recovery function in `RewardSupplier` to reclaim stray tokens, and `request_funds` is not publicly callable — it is only triggered via `update_unclaimed_rewards_from_staking_contract`, which is restricted to the staking contract. [5](#0-4) 

### Impact Explanation

**Temporary freezing of unclaimed yield (High).**

When the attack succeeds, `claim_rewards` reverts because the contract's actual STRK balance is less than `unclaimed_rewards`. Stakers and pool members cannot withdraw earned rewards until a new L1 mint request is sent and fulfilled. L1→L2 bridge latency (typically hours to days) means the freeze is not instantaneous to resolve. The `unclaimed_rewards` accounting variable is correct; only the physical token balance is insufficient, so the freeze is temporary but real.

### Likelihood Explanation

**Medium.** The attacker must spend their own STRK tokens. However:
- No privileged access is required — any address can call `STRK.transfer`.
- The amount needed equals roughly `unclaimed_rewards + threshold − real_balance`, which can be modest relative to the protocol's total stake.
- A griefing actor (e.g., a competing protocol, a short-seller) has a plausible motive.
- The attack can be timed to coincide with a large reward epoch to maximize disruption.

### Recommendation

Replace the live `balance_of` call in `request_funds` with an internally tracked balance variable that is incremented only when tokens arrive via `on_receive` (the authorised bridge path) and decremented when `claim_rewards` transfers tokens out. This mirrors the fix applied to `BullStrategy` in the referenced PR: rely on internal accounting rather than the raw ERC-20 balance.

Alternatively, add a `farm` function restricted to the contract owner that allows recovery of excess STRK (tokens beyond `unclaimed_rewards`), and document that the live balance must never be used as a trust anchor for mint-request decisions.

### Proof of Concept

1. Observe current state: `unclaimed_rewards = R`, `balance = B`, `l1_pending_requested_amount = P`, where `B + P < R + threshold` (a mint request is legitimately needed).
2. Attacker calls `STRK.transfer(reward_supplier_address, R + threshold − B − P + 1)` directly.
3. `balance` is now `R + threshold − P + 1`; `l1_pending_requested_amount` is unchanged at `P`.
4. Staking contract calls `update_unclaimed_rewards_from_staking_contract(rewards)`, which internally calls `request_funds(R)`.
5. Inside `request_funds`: `credit = (R + threshold − P + 1) + P = R + threshold + 1 ≥ R + threshold` → **no L1 mint request is sent**.
6. Staking contract calls `claim_rewards(R)` → `checked_transfer(staking_contract, R)` succeeds, consuming the attacker's tokens. `balance` drops to `threshold + 1 − P`.
7. New rewards accrue: staking contract calls `update_unclaimed_rewards_from_staking_contract(rewards2)` → `unclaimed_rewards = rewards2`. `request_funds` now sends a request, but L1 fulfillment takes hours.
8. Before L1 fulfillment, staking contract calls `claim_rewards(rewards2)`. `checked_transfer` attempts to send `rewards2` STRK but `balance = threshold + 1 − P < rewards2` → **revert**. Staker reward claims are frozen until the L1 mint arrives. [6](#0-5)

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
