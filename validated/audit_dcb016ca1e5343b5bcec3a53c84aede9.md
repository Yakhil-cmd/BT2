Audit Report

## Title
ckERC20 Withdrawal Requests Stuck Indefinitely When Gas Fees Exceed Pre-Burned Budget — No Cancel or Reimbursement Path - (File: rs/ethereum/cketh/minter/src/withdraw.rs)

## Summary

When a user calls `withdraw_erc20`, the minter burns ckETH (gas budget) and ckERC20 tokens immediately, storing `max_transaction_fee = 2 * base_fee_at_request + priority` in the queued `Erc20WithdrawalRequest`. If Ethereum gas fees spike beyond this 2× buffer before the background task processes the request, `create_transaction` returns `InsufficientTransactionFee` and the request is silently rescheduled to the back of the queue — indefinitely — with no user-facing cancel or reimbursement path. The user's already-burned ckETH and ckERC20 are locked with no corresponding Ethereum settlement for as long as gas fees remain elevated.

## Finding Description

**Step 1 — Burn at request time.**
`withdraw_erc20` in `main.rs` calls `estimate_erc20_transaction_fee()` → `lazy_refresh_gas_fee_estimate()` → `GasFeeEstimate::to_price()`, which sets `max_fee_per_gas = 2 * base_fee + priority` (confirmed in `tx.rs` `checked_estimate_max_fee_per_gas`). The resulting `max_transaction_fee = max_fee_per_gas * 65_000` is burned from the user's ckETH account and stored verbatim as `Erc20WithdrawalRequest::max_transaction_fee`.

**Step 2 — Re-estimation at processing time.**
`process_retrieve_eth_requests` in `withdraw.rs` calls `lazy_refresh_gas_fee_estimate()` again (up to 60 s stale) and passes the fresh estimate to `create_transactions_batch` → `create_transaction`.

**Step 3 — The guard that fails.**
Inside `create_transaction` for `CkErc20`, the check is:
```
actual_min_max_fee_per_gas = base_fee_now + priority_now
request_max_fee_per_gas   = max_transaction_fee / 65_000
                          = (2 * base_fee_at_request + priority_at_request)
if actual > request → InsufficientTransactionFee
```
This fires whenever `base_fee_now + priority_now > 2 * base_fee_at_request + priority_at_request`, i.e., roughly when the base fee more than doubles.

**Step 4 — Silent reschedule, no reimbursement.**
`create_transactions_batch` handles the error by calling `reschedule_withdrawal_request`, which moves the request to the back of `pending_withdrawal_requests`. The request is never moved into `maybe_reimburse` (that only happens via `record_created_transaction` on success). There is no timeout, no cancel endpoint, and no reimbursement trigger for this failure mode. The user's burned ckETH and ckERC20 remain locked until gas fees drop below the original 2× budget — which may take hours, days, or longer during sustained congestion.

## Impact Explanation

Concrete impact: **user funds locked in ckERC20 withdrawal with no cancel or reimbursement path**. The user has irreversibly burned ckETH (gas budget) and ckERC20 tokens on the IC. No Ethereum transaction is sent. The request cycles in the pending queue indefinitely. This matches the allowed bounty impact: *"Significant Chain Fusion, ck-token, ledger… security impact with concrete user or protocol harm"* — **High ($2,000–$10,000)**. The impact is not Critical because funds are eventually recoverable if gas fees drop; it is not merely informational because the lockup is unbounded and user-initiated with no escape hatch.

## Likelihood Explanation

Any unprivileged user calling `withdraw_erc20` is exposed. No special privileges are required. Ethereum base fees have historically spiked 5–20× within minutes during high-demand events (NFT mints, protocol launches, market crashes). The minter's background task runs on a timer (minutes apart), creating a window during which gas fees can change substantially. The 2× buffer is insufficient for such spikes. The condition is repeatable and requires no attacker — it is triggered by normal Ethereum network volatility.

## Recommendation

Two complementary fixes:

1. **Use the burned estimate for transaction creation.** Store the `GasFeeEstimate` snapshot inside `Erc20WithdrawalRequest` at burn time. In `create_transaction`, use the stored `max_fee_per_gas` directly (already equal to `request_max_fee_per_gas`) without re-checking against the live `min_max_fee_per_gas`. The transaction will always be creatable with the budget the user already paid; EIP-1559 semantics guarantee it will be mined once the base fee drops below `max_fee_per_gas`.

2. **Add a reimbursement path for the stuck case.** If `create_transaction` returns `InsufficientTransactionFee` for a `CkErc20` request that has been pending beyond a configurable threshold, move it into `maybe_reimburse` so the user's burned ckETH and ckERC20 are returned (minus a penalty fee), mirroring the existing ckETH burn-failure reimbursement path already present in `withdraw_erc20`.

## Proof of Concept

1. Ethereum base fee = 10 gwei. User calls `withdraw_erc20`. Minter estimates `max_fee_per_gas = 2*10 + 1.5 = 21.5 gwei`. Burns `21.5 * 65_000 = 1_397_500 gwei` of ckETH and the full ckERC20 amount. `max_transaction_fee = 1_397_500 gwei` stored in request.

2. Before the background task runs, Ethereum base fee spikes to 25 gwei (e.g., popular NFT mint). Background task calls `lazy_refresh_gas_fee_estimate()`: `base_fee_now = 25`, `priority_now = 1.5`. `actual_min_max_fee_per_gas = 26.5 gwei`. `request_max_fee_per_gas = 21.5 gwei`. **26.5 > 21.5 → `InsufficientTransactionFee`.**

3. `create_transactions_batch` calls `reschedule_withdrawal_request`. Request moves to back of queue. No entry in `maybe_reimburse`. No reimbursement scheduled.

4. Background task runs again next cycle. Gas fees still elevated. Same result. Repeat indefinitely.

5. **Reproducible unit test plan:** In `rs/ethereum/cketh/minter/src/state/transactions/tests.rs`, create a `ckerc20_withdrawal_request_with_index` with `max_transaction_fee` derived from `GasFeeEstimate { base_fee: 10 gwei, priority: 1.5 gwei }`. Call `create_transaction` with a fresh `GasFeeEstimate { base_fee: 25 gwei, priority: 1.5 gwei }`. Assert `Err(InsufficientTransactionFee)`. Then assert the request remains in `pending_withdrawal_requests` and `maybe_reimburse` is empty — confirming no reimbursement is scheduled.