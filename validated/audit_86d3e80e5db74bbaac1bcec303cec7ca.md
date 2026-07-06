### Title
Attacker-Donated STRK Tokens Suppress L1 Mint Requests, Causing `claim_rewards` to Fail — (`src/reward_supplier/reward_supplier.cairo`)

### Summary

The `request_funds` internal function in `RewardSupplier` reads the contract's live token balance to decide whether to send L1 mint requests. Because any address can call `STRK.transfer(reward_supplier, X)` directly — bypassing the `on_receive` bridge hook — an attacker can inflate the contract's balance without updating `l1_pending_requested_amount`. This makes `request_funds` believe sufficient credit exists and suppresses future L1 mint requests. As `unclaimed_rewards` grows each epoch while the actual balance stagnates, `claim_rewards` eventually fails via `checked_transfer`, freezing reward distribution to all stakers and delegators.

---

### Finding Description

`request_funds` is called every epoch inside `update_unclaimed_rewards_from_staking_contract`:

```
fn request_funds(ref self: ContractState, unclaimed_rewards: Amount) {
    let balance: Amount = token_dispatcher
        .balance_of(account: get_contract_address())   // ← reads live balance
        ...;
    let credit = balance + l1_pending_requested_amount;
    let debit  = unclaimed_rewards;
    if credit < debit + threshold {
        // send L1 mint request
    }
}
``` [1](#0-0) 

The `on_receive` bridge hook is the only path that reduces `l1_pending_requested_amount` when tokens arrive:

```
fn on_receive(...) {
    assert!(get_caller_address() == self.starkgate_address.read(), ...);
    ...
    l1_pending_requested_amount -= amount_u128;
}
``` [2](#0-1) 

A direct ERC-20 `transfer` to the contract address never calls `on_receive`, so `l1_pending_requested_amount` is not updated. The donated tokens inflate `balance`, inflate `credit`, and push `credit` above `debit + threshold`, silencing L1 mint requests.

Meanwhile, `update_unclaimed_rewards_from_staking_contract` keeps incrementing `unclaimed_rewards` each epoch:

```
let unclaimed_rewards = self.unclaimed_rewards.read() + rewards;
self.unclaimed_rewards.write(unclaimed_rewards);
self.request_funds(:unclaimed_rewards);
``` [3](#0-2) 

Once `unclaimed_rewards` exceeds the actual balance, `claim_rewards` panics inside `checked_transfer`:

```
token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
``` [4](#0-3) 

---

### Impact Explanation

`claim_rewards` is the only path through which the staking contract receives STRK to pay stakers and delegators. A failed `checked_transfer` reverts the entire reward-distribution call chain, freezing all unclaimed yield for every staker and delegator until the contract's balance is manually replenished or the attacker stops donating. This matches **Temporary freezing of funds / unclaimed yield** (High).

---

### Likelihood Explanation

Any unprivileged address holding STRK can execute this attack with a single ERC-20 `transfer` call. No privileged access, bridge compromise, or governance action is required. The attacker sacrifices tokens but causes disproportionate protocol damage. The attack is repeatable: the attacker can re-donate whenever the balance recovers, making the freeze indefinitely renewable at the attacker's discretion.

---

### Recommendation

Replace the live `balance_of` read in `request_funds` with a tracked internal accounting variable that is incremented only through `on_receive` (bridge deposits) and decremented through `claim_rewards` (outflows). This mirrors the `unclaimed_rewards` pattern already used in the contract and removes the ability for external token donations to influence the L1 mint-request logic.

---

### Proof of Concept

1. Deploy the system normally; `RewardSupplier` has `balance = B`, `unclaimed_rewards = U ≤ B`.
2. Attacker calls `STRK.transfer(reward_supplier_address, X)` where `X` is large enough that `B + X ≥ U + N·R_per_epoch + threshold` for `N` target epochs.
3. Each epoch the staking contract calls `update_unclaimed_rewards_from_staking_contract(R)`:
   - `unclaimed_rewards` grows to `U + k·R` after `k` epochs.
   - `request_funds` sees `credit = B + X ≥ debit + threshold` → no L1 mint request sent.
4. After `N` epochs, `unclaimed_rewards = U + N·R > B + X` (the donated tokens have been consumed by prior `claim_rewards` calls while no new L1 mints arrived).
5. The staking contract calls `claim_rewards(R')` where `R' ≤ unclaimed_rewards` but `R' > actual_balance` → `checked_transfer` panics → reward distribution reverts for all stakers and delegators.

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

**File:** src/reward_supplier/reward_supplier.cairo (L218-219)
```text
            let token_dispatcher = self.token_dispatcher.read();
            token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
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
