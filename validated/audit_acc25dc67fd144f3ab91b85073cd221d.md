### Title
Attacker Can Suppress L1 Mint Requests by Donating Tokens to Inflate `balance_of` in `request_funds` - (File: `src/reward_supplier/reward_supplier.cairo`)

### Summary

`RewardSupplier::request_funds` uses `token_dispatcher.balance_of(get_contract_address())` — the live on-chain token balance — as the "credit" side of its liquidity check. Because any address can transfer STRK directly to the contract without going through `on_receive`, an attacker can inflate this balance, suppress L1 mint requests, and eventually cause reward claims to revert once the donated tokens are consumed.

### Finding Description

`request_funds` is the internal function that decides whether to send a cross-chain mint request to the L1 `RewardSupplier`. Its logic is:

```cairo
fn request_funds(ref self: ContractState, unclaimed_rewards: Amount) {
    let token_dispatcher = self.token_dispatcher.read();
    let balance: Amount = token_dispatcher
        .balance_of(account: get_contract_address())   // ← live balance, not tracked
        .try_into()
        .expect_with_err(InternalError::BALANCE_ISNT_AMOUNT_TYPE);

    let mut l1_pending_requested_amount = self.l1_pending_requested_amount.read();
    let credit = balance + l1_pending_requested_amount;   // ← inflatable by donation
    let debit = unclaimed_rewards;

    let base_mint_amount = self.base_mint_amount.read();
    let threshold = compute_threshold(base_mint_amount);
    if credit < debit + threshold {
        // send L1 mint request
    }
}
``` [1](#0-0) 

The contract has no mechanism to distinguish tokens that arrived legitimately (via `on_receive` from StarkGate) from tokens donated directly via a plain ERC-20 `transfer`. `on_receive` only decrements `l1_pending_requested_amount`; it does not update any "tracked balance" variable. Therefore, a direct ERC-20 donation silently inflates `balance` without any corresponding bookkeeping entry. [2](#0-1) 

`request_funds` is called every time `update_unclaimed_rewards_from_staking_contract` is invoked (i.e., on every successful attestation): [3](#0-2) 

`claim_rewards` checks `amount <= unclaimed_rewards` and then calls `checked_transfer`. If the actual token balance is insufficient, `checked_transfer` reverts, freezing all reward claims: [4](#0-3) 

### Impact Explanation

**Attack sequence:**

1. Attacker calls `STRK.transfer(reward_supplier_address, D)` — a permissionless ERC-20 transfer.
2. `balance_of(reward_supplier)` increases by `D`.
3. On the next attestation, `request_funds` computes `credit = (B + D) + P`. If `credit >= unclaimed_rewards + threshold`, no L1 mint request is sent.
4. Legitimate reward claims consume the donated tokens alongside real tokens. `unclaimed_rewards` decreases as claims are made, but the L1 pipeline was never refilled.
5. Once the donated tokens are exhausted, `balance < amount` for any pending `claim_rewards` call, causing `checked_transfer` to revert.
6. The freeze persists until the next attestation triggers a new L1 mint request **and** the L1→L2 bridge delay elapses (typically hours to days).

During this window, stakers and delegators cannot claim their earned STRK rewards. This constitutes **temporary freezing of unclaimed yield**, which is a **High** impact per the allowed scope.

### Likelihood Explanation

- The entry path is fully permissionless: any address can call `STRK.transfer` to the `RewardSupplier` contract.
- The attacker must sacrifice the donated tokens (they are consumed by legitimate claims), making this a griefing attack with a direct cost.
- The required donation amount is bounded by `threshold = compute_threshold(base_mint_amount)`, which is a protocol-configured value. A well-resourced attacker or a competitor with a profit motive (e.g., suppressing a rival staker's reward claims) could execute this.
- Likelihood: **Medium** — economically costly but technically trivial to execute.

### Recommendation

Replace the live `balance_of` call with an internally tracked balance variable that is only updated through controlled entry points (`on_receive`, `claim_rewards`). This mirrors the fix described in the external report: use a calculated/tracked value rather than the raw account balance.

```cairo
// Instead of:
let balance: Amount = token_dispatcher
    .balance_of(account: get_contract_address())
    .try_into()...;

// Use a storage variable updated only in on_receive and claim_rewards:
let balance: Amount = self.tracked_balance.read();
```

### Proof of Concept

1. Deploy the protocol normally. Let `unclaimed_rewards = U`, `balance = B`, `l1_pending_requested_amount = P`, with `B + P = U + threshold` (normal steady state).
2. Attacker calls `STRK.transfer(reward_supplier, threshold + 1)`.
3. Next attestation calls `update_unclaimed_rewards_from_staking_contract(rewards: R)` → `unclaimed_rewards = U + R` → `request_funds(U + R)`.
4. Inside `request_funds`: `balance = B + threshold + 1`, `credit = B + threshold + 1 + P = U + 2*threshold + 1`. Since `credit = U + 2*threshold + 1 >= (U + R) + threshold` for small `R`, no L1 mint request is sent.
5. Stakers claim rewards; the donated `threshold + 1` tokens are consumed alongside real tokens.
6. Eventually `balance < unclaimed_rewards`; `claim_rewards` reverts with an ERC-20 transfer failure.
7. All staker and delegator reward claims are frozen until the next attestation triggers a new L1 mint request and the bridge delay elapses.

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
