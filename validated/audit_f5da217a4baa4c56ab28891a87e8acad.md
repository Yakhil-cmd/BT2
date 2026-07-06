### Title
Token Donation Suppresses L1 Mint Requests, Causing Temporary Reward Claim Failures - (File: `src/reward_supplier/reward_supplier.cairo`)

### Summary

The `request_funds` internal function in `RewardSupplier` reads the contract's live ERC20 token balance via `balance_of` to decide whether to send L1 mint requests. Because any unprivileged actor can donate STRK tokens directly to the contract, an attacker can inflate the apparent `credit`, suppressing necessary L1 mint requests. Once the donated tokens are consumed by legitimate reward claims, the contract's balance falls below `unclaimed_rewards`, causing subsequent `claim_rewards` calls (and thus staker/delegator reward payouts) to fail until the next L1 mint cycle completes.

### Finding Description

In `request_funds` (called every epoch from `update_unclaimed_rewards_from_staking_contract`):

```cairo
// src/reward_supplier/reward_supplier.cairo lines 301-331
fn request_funds(ref self: ContractState, unclaimed_rewards: Amount) {
    let token_dispatcher = self.token_dispatcher.read();
    let balance: Amount = token_dispatcher
        .balance_of(account: get_contract_address())   // <-- live balance, manipulable
        .try_into()
        .expect_with_err(InternalError::BALANCE_ISNT_AMOUNT_TYPE);

    let mut l1_pending_requested_amount = self.l1_pending_requested_amount.read();
    let credit = balance + l1_pending_requested_amount; // inflated by donation
    let debit = unclaimed_rewards;

    let base_mint_amount = self.base_mint_amount.read();
    let threshold = compute_threshold(base_mint_amount); // base_mint_amount / 2
    if credit < debit + threshold {                      // condition suppressed
        // ... send L1 mint request messages
    }
}
``` [1](#0-0) 

The `credit` variable is computed as `balance_of(self) + l1_pending_requested_amount`. Because `balance_of` reflects the raw ERC20 balance, any STRK tokens sent directly to the contract (outside of the StarkGate `on_receive` path) inflate `credit` without updating any internal accounting. The `on_receive` callback only decrements `l1_pending_requested_amount` when tokens arrive via StarkGate; a direct ERC20 transfer bypasses it entirely. [2](#0-1) 

The `claim_rewards` function then performs a `checked_transfer` of actual tokens to the staking contract:

```cairo
// lines 205-219
fn claim_rewards(ref self: ContractState, amount: Amount) {
    ...
    let unclaimed_rewards = self.unclaimed_rewards.read();
    assert!(amount <= unclaimed_rewards, "{}", GenericError::AMOUNT_TOO_HIGH);
    self.unclaimed_rewards.write(unclaimed_rewards - amount);
    token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
}
``` [3](#0-2) 

If the actual token balance is less than `amount`, `checked_transfer` reverts, blocking all reward payouts.

### Impact Explanation

**Attack path:**

1. Attacker donates `D` STRK tokens directly to the `RewardSupplier` contract address (standard ERC20 transfer, no permission required).
2. In the current epoch, `update_unclaimed_rewards_from_staking_contract` is called by the staking contract; `request_funds` computes `credit = (B + D) + P` where `B` is the pre-existing balance and `P` is `l1_pending_requested_amount`. If `credit >= debit + threshold`, no L1 mint request is emitted.
3. Legitimate reward claims consume the donated tokens: `balance` falls to `B + D - claimed`.
4. In subsequent epochs, `unclaimed_rewards` continues to grow (new epoch rewards are added), but no new L1 mint request was sent. The balance may now be less than `unclaimed_rewards`.
5. `claim_rewards` is called by the staking contract on behalf of stakers/delegators; `checked_transfer` fails because `balance < amount`, reverting the entire reward distribution.

The window of failure persists until the next epoch's `request_funds` detects the deficit, sends a new L1 mint request, and the L1→L2 bridge message is processed (which can take hours to days).

**Impact:** Temporary freezing of unclaimed yield for all stakers and delegators. No funds are permanently lost, but reward claims are blocked for the duration of the L1-L2 messaging round-trip.

### Likelihood Explanation

Any unprivileged address can execute a standard ERC20 `transfer` to the `RewardSupplier` contract. The cost to the attacker is the donated tokens themselves (no recovery). The required donation amount equals `debit + threshold - credit` at the time of the attack, which scales with `base_mint_amount` (set at deployment). For a protocol with a large `base_mint_amount`, the cost is high; for a protocol near the threshold, a small donation suffices. Likelihood is **low** due to the direct financial cost to the attacker, but the entry path is fully permissionless.

### Recommendation

Replace the live `balance_of` call in `request_funds` with an internal accounting variable that tracks only tokens received through authorized channels (i.e., via `on_receive` from StarkGate). Specifically:

- Maintain a storage variable `tracked_balance` that is incremented only inside `on_receive` and decremented inside `claim_rewards`.
- In `request_funds`, replace `balance_of(get_contract_address())` with `self.tracked_balance.read()`.

This eliminates the ability of arbitrary token donations to influence the L1 mint request logic.

### Proof of Concept

1. Deploy the system normally. Let `unclaimed_rewards = U`, `balance = B`, `l1_pending = P`, with `B + P < U + threshold` (so a mint request would normally be sent).
2. Before the epoch's `update_unclaimed_rewards_from_staking_contract` call, attacker calls `strk_token.transfer(reward_supplier_address, D)` where `D = (U + threshold) - (B + P) + 1`.
3. `update_unclaimed_rewards_from_staking_contract` is called; `request_funds` computes `credit = B + D + P = U + threshold + 1 >= U + threshold`. No mint request is sent.
4. Staking contract calls `claim_rewards(amount: U)`. `checked_transfer` succeeds (balance = `B + D - U = threshold + 1 > 0`).
5. Next epoch: new rewards `R` are added. `unclaimed_rewards = R`. `balance = threshold + 1 - (any further claims)`. If `balance < R`, `claim_rewards(R)` reverts via `checked_transfer`.
6. All staker and delegator reward payouts are blocked until the next successful L1 mint cycle. [4](#0-3) [5](#0-4)

### Citations

**File:** src/reward_supplier/reward_supplier.cairo (L205-219)
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

**File:** src/reward_supplier/utils.cairo (L12-14)
```text
/// Compute the threshold for requesting funds from L1 Reward Supplier.
pub(crate) fn compute_threshold(base_mint_amount: Amount) -> Amount {
    base_mint_amount / 2
```
