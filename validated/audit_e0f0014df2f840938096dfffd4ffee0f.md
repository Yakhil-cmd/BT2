### Title
Balance Inflation in `request_funds` Suppresses L1 Mint Requests, Enabling Temporary Reward Payment Freeze — (File: `src/reward_supplier/reward_supplier.cairo`)

---

### Summary

The `request_funds` function in `RewardSupplier` derives its `credit` value from the contract's live ERC20 `balance_of` reading. Any unprivileged actor can directly transfer STRK tokens to the `RewardSupplier` address, inflating `balance` and therefore `credit`, causing the L1 mint-request gate to stay closed even when the protocol genuinely needs more tokens. Once the inflated balance is consumed by legitimate reward claims, the contract has no tokens left to honour further `claim_rewards` calls, temporarily freezing staker and delegator yield.

---

### Finding Description

In `InternalRewardSupplierFunctions::request_funds` the contract reads its own live token balance:

```cairo
let balance: Amount = token_dispatcher
    .balance_of(account: get_contract_address())
    .try_into()
    .expect_with_err(InternalError::BALANCE_ISNT_AMOUNT_TYPE);

let credit = balance + l1_pending_requested_amount;
let debit  = unclaimed_rewards;

let threshold = compute_threshold(base_mint_amount);   // = base_mint_amount / 2
if credit < debit + threshold {
    // … send L1 mint request …
}
``` [1](#0-0) 

`balance` is the raw ERC20 balance of the contract address. Because ERC20 `transfer` is permissionless, any actor can call `STRK.transfer(reward_supplier_address, amount)` without going through any protocol entry-point. This inflates `balance`, raises `credit`, and keeps the condition `credit < debit + threshold` false, suppressing the L1 mint request.

`compute_threshold` returns `base_mint_amount / 2`, so the attacker only needs to donate enough tokens to cover the gap between the current credit and `debit + threshold`. [2](#0-1) 

The `claim_rewards` function later transfers tokens out of the contract:

```cairo
token_dispatcher.checked_transfer(recipient: staking_contract, amount: amount.into());
``` [3](#0-2) 

If the contract's balance has been depleted (because the attacker's donated tokens were consumed by legitimate claims and no L1 replenishment was triggered), `checked_transfer` panics, reverting every `claim_rewards` call until L1 tokens eventually arrive.

---

### Impact Explanation

**Temporary freezing of unclaimed yield (High).**

Stakers and delegators call `claim_rewards` on the staking contract, which in turn calls `RewardSupplier::claim_rewards`. If the reward supplier's token balance is zero while `unclaimed_rewards > 0`, the ERC20 transfer reverts and no staker or delegator can collect earned rewards until the L1→L2 bridge message is processed (which can take hours to days). The `unclaimed_rewards` accounting is unaffected — the debt is real — but the tokens are not present to settle it.

---

### Likelihood Explanation

Any holder of STRK tokens can execute this with a single `transfer` call. The cost to the attacker is the donated tokens (which are permanently locked in the contract and eventually consumed by legitimate claims — the attacker receives nothing back). The required donation amount equals `(debit + threshold) - credit` at the moment of attack, which can be small when the contract is near its replenishment threshold. The attack is repeatable: each epoch the attacker can top up the balance again to keep suppressing L1 requests.

---

### Recommendation

Replace the live `balance_of` read with an internally-tracked balance variable that is incremented only on verified inflows (i.e., via `on_receive` from the bridge) and decremented on `claim_rewards` transfers. This mirrors the fix applied to the original Controller.sol report: stop deriving the critical value from the raw address balance, because external actors can freely manipulate it.

---

### Proof of Concept

1. Protocol state: `balance = B`, `unclaimed_rewards = U`, `l1_pending_requested_amount = P`, `threshold = T`. Assume `B + P` is just above `U + T` (contract is healthy, no L1 request pending).
2. Attacker calls `STRK.transfer(reward_supplier, A)` where `A` is small (e.g., 1 token). Now `balance = B + A`, `credit = B + A + P`.
3. Each epoch, `update_unclaimed_rewards_from_staking_contract` is called → `request_funds` runs → `credit = B + A + P >= U_new + T` → no L1 request is sent.
4. Stakers and delegators call `claim_rewards`; the contract pays out using `B + A` tokens. `balance` decreases with each claim.
5. Eventually `balance` reaches 0 while `unclaimed_rewards` is still positive (new rewards have accrued but no L1 replenishment was triggered).
6. The next `claim_rewards` call hits `checked_transfer` with `balance = 0` → transfer panics → all staker and delegator reward claims revert.
7. The freeze persists until an L1→L2 bridge message (triggered only after the balance finally dropped below the threshold in a subsequent `request_funds` call) is processed on L2. [4](#0-3) [1](#0-0)

### Citations

**File:** src/reward_supplier/reward_supplier.cairo (L204-219)
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

**File:** src/reward_supplier/utils.cairo (L13-14)
```text
pub(crate) fn compute_threshold(base_mint_amount: Amount) -> Amount {
    base_mint_amount / 2
```
