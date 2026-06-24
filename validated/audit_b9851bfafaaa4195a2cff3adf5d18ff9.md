Audit Report

## Title
Missing Reimbursement Path for ckERC20 Withdrawals When Gas Fees Exceed Locked `max_transaction_fee` - (`File: rs/ethereum/cketh/minter/src/withdraw.rs`)

## Summary

When a ckERC20 withdrawal request is accepted, both ckETH (gas fee) and ckERC20 tokens are burned upfront with a `max_transaction_fee` fixed at call time. If Ethereum gas fees subsequently spike so that the locked budget is insufficient, the minter's timer loop calls `reschedule_withdrawal_request` indefinitely with no reimbursement path for the pending-queue case, and only logs an error for the already-sent case. Both ckETH and ckERC20 tokens remain burned with no mechanism for the user to recover them, and a stuck sent transaction blocks all subsequent nonces.

## Finding Description

**Root cause — pending queue path:**

In `create_transactions_batch` (`rs/ethereum/cketh/minter/src/withdraw.rs` L249–293), when `create_transaction` returns `CreateTransactionError::InsufficientTransactionFee` for a `CkErc20` request, the handler calls `reschedule_withdrawal_request` and emits only a log message:

```rust
mutate_state(|s| s.eth_transactions.reschedule_withdrawal_request(request));
```

No `FailedErc20WithdrawalRequest` event is emitted, no `ReimbursementRequest` is recorded, and no ckETH or ckERC20 mint-back is scheduled. The request loops at the back of the queue on every timer tick indefinitely. [1](#0-0) 

The fee check that triggers this path compares `gas_fee_estimate.min_max_fee_per_gas()` (= `base_fee_per_gas + max_priority_fee_per_gas`) against `request.max_transaction_fee / gas_limit`. The budget was set at withdrawal time as `(2 * base_fee_per_gas_T0 + max_priority_fee_per_gas_T0) * 65_000`, giving roughly 2× headroom on the base fee. Any sustained spike beyond that headroom causes indefinite rescheduling. [2](#0-1) 

**Root cause — already-sent path:**

In `resubmit_transactions_batch` (`rs/ethereum/cketh/minter/src/withdraw.rs` L208–246), when `create_resubmit_transactions` returns `ResubmitTransactionError::InsufficientTransactionFee`, the handler only logs:

```rust
Err(e) => {
    log!(INFO, "Failed to resubmit transaction: {e:?}");
}
```

No reimbursement is triggered. The transaction remains in `sent_tx` with its original `max_fee_per_gas`. If the current `base_fee_per_gas` permanently exceeds that value, the transaction can never be mined, the minter cannot increase the fee, and the nonce is blocked — preventing all subsequent ckETH and ckERC20 withdrawals from being processed. [3](#0-2) [4](#0-3) 

**Contrast with existing reimbursement path:**

When the ckERC20 burn fails *during* `withdraw_erc20` itself, a `FailedErc20WithdrawalRequest` event is emitted and the ckETH is reimbursed. This path is entirely absent for the timer-based processing failure. [5](#0-4) 

**The `max_transaction_fee` is immutable after acceptance:** [6](#0-5) 

**Gas fee estimate is cached up to 60 seconds**, so a user calling `withdraw_erc20` just before a spike will have their budget locked at the pre-spike value. [7](#0-6) 

**Note on prior partial fix:** Upgrade proposal `minter_upgrade_2024_08_05.md` (commit `f420b4d6e`) fixed "unnecessarily delayed" ckERC20 withdrawals by switching the comparison from `estimate_max_fee_per_gas()` (2× base fee) to `min_max_fee_per_gas()` (1× base fee), reducing false positives. However, the absence of a reimbursement path when fees genuinely exceed the budget was not addressed and remains in the current codebase. [8](#0-7) 

## Impact Explanation

This is a **High** severity finding matching: *"Significant Chain Fusion, ck-token, ledger, Rosetta, boundary/API, XRC, Internet Identity, NNS, SNS, or infrastructure security impact with concrete user or protocol harm."*

- **Per-user fund lock**: Both ckETH (gas fee) and ckERC20 tokens are burned at withdrawal time. If gas fees remain elevated, the user's funds are locked indefinitely with no reimbursement path and no cancellation mechanism.
- **Protocol-level nonce blocking**: A single stuck sent transaction blocks all subsequent nonces, halting all ckETH and ckERC20 withdrawals for all users until the stuck transaction is resolved.
- **No user recourse**: Unlike the ckERC20 burn failure path (which reimburses ckETH), there is no event type, no state transition, and no code path that returns funds to the user when the timer-based processing fails due to insufficient fees.

## Likelihood Explanation

Ethereum gas fees are highly volatile. Spikes of 3–10× within minutes are documented during network congestion (NFT mints, protocol launches, market events). The `max_transaction_fee` budget provides only ~2× headroom on the base fee at withdrawal time. A user calling `withdraw_erc20` during moderate congestion that then escalates will have their request stuck for the duration of the spike. The ckBTC minter experienced a real-world stuck-withdrawal incident (documented in `rs/bitcoin/ckbtc/mainnet/minter_upgrade_2025_06_27.md`) confirming this class of issue is non-theoretical for chain-fusion minters. No special privileges are required — any user calling `withdraw_erc20` on the production minter (`sv3dd-oaaaa-aaaar-qacoa-cai`) is exposed. [9](#0-8) 

## Recommendation

1. **Pending queue**: When `create_transaction` returns `InsufficientTransactionFee` for a `WithdrawalRequest::CkErc20` request, emit a `FailedErc20WithdrawalRequest` event (reimbursing ckETH) and a `CkErc20`-indexed `ReimbursementRequest` (reimbursing ckERC20 tokens), analogous to the existing path at `main.rs` L506–531. Distinguish this from the `CkEth` case, which can simply reschedule since the withdrawal amount covers the fee.

2. **Sent transactions**: When `create_resubmit_transactions` returns `InsufficientTransactionFee` for a ckERC20 transaction, schedule reimbursement of the ckERC20 tokens (the ckETH gas fee is consumed by the on-chain transaction fee regardless of outcome).

3. **Alternatively**: Implement a maximum queue age for ckERC20 withdrawal requests. If a request has been pending beyond a configurable threshold without being processable, trigger the reimbursement flow.

## Proof of Concept

**Deterministic integration test plan** (using the existing `CkErc20Setup` state machine test harness in `rs/ethereum/cketh/minter/tests/ckerc20.rs`):

1. Set up a `CkErc20Setup` with a user holding ckETH and ckUSDC.
2. Call `withdraw_erc20` at a moderate gas price (e.g., `base_fee = 10 gwei`), recording `cketh_burn_index` and `ckerc20_burn_index`.
3. Advance the timer and inject a fee history response with `base_fee = 500 gwei` (50× spike, well above the 2× budget).
4. Assert that `create_transactions_batch` calls `reschedule_withdrawal_request` (request stays in `pending_withdrawal_requests`).
5. Assert that **no** `FailedErc20WithdrawalRequest` event is emitted.
6. Assert that the user's ckETH balance has not been restored (ckETH remains burned).
7. Assert that the user's ckUSDC balance has not been restored (ckERC20 remains burned).
8. Advance time by days and repeat steps 3–7 to confirm the request loops indefinitely.

The existing test `should_process_withdrawal_when_price_increases_moderately` already demonstrates the rescheduling behavior (step 4) but does not assert the absence of reimbursement, confirming the gap. [10](#0-9)

### Citations

**File:** rs/ethereum/cketh/minter/src/withdraw.rs (L242-244)
```rust
            Err(e) => {
                log!(INFO, "Failed to resubmit transaction: {e:?}");
            }
```

**File:** rs/ethereum/cketh/minter/src/withdraw.rs (L281-291)
```rust
            Err(CreateTransactionError::InsufficientTransactionFee {
                cketh_ledger_burn_index: ledger_burn_index,
                allowed_max_transaction_fee: withdrawal_amount,
                actual_max_transaction_fee: max_transaction_fee,
            }) => {
                log!(
                    INFO,
                    "[create_transactions_batch]: Withdrawal request with burn index {ledger_burn_index} has insufficient amount {withdrawal_amount:?} to cover transaction fees: {max_transaction_fee:?}. Request moved back to end of queue."
                );
                mutate_state(|s| s.eth_transactions.reschedule_withdrawal_request(request));
            }
```

**File:** rs/ethereum/cketh/minter/src/state/transactions/mod.rs (L146-152)
```rust
pub struct Erc20WithdrawalRequest {
    /// Amount of burn ckETH that can be used to pay for the Ethereum transaction fees.
    #[n(0)]
    pub max_transaction_fee: Wei,
    /// The ERC-20 amount that the receiver will get.
    #[n(1)]
    pub withdrawal_amount: Erc20Value,
```

**File:** rs/ethereum/cketh/minter/src/state/transactions/mod.rs (L618-631)
```rust
                Err(crate::tx::ResubmitTransactionError::InsufficientTransactionFee {
                    allowed_max_transaction_fee,
                    actual_max_transaction_fee,
                }) => {
                    transactions_to_resubmit.push(Err(
                        ResubmitTransactionError::InsufficientTransactionFee {
                            ledger_burn_index: *burn_index,
                            transaction_nonce: *nonce,
                            allowed_max_transaction_fee,
                            max_transaction_fee: actual_max_transaction_fee,
                        },
                    ));
                    return transactions_to_resubmit;
                }
```

**File:** rs/ethereum/cketh/minter/src/state/transactions/mod.rs (L1155-1168)
```rust
            let request_max_fee_per_gas = request
                .max_transaction_fee
                .into_wei_per_gas(gas_limit)
                .expect("BUG: gas_limit should be non-zero");
            let actual_min_max_fee_per_gas = gas_fee_estimate.min_max_fee_per_gas();
            if actual_min_max_fee_per_gas > request_max_fee_per_gas {
                return Err(CreateTransactionError::InsufficientTransactionFee {
                    cketh_ledger_burn_index: request.cketh_ledger_burn_index,
                    allowed_max_transaction_fee: request.max_transaction_fee,
                    actual_max_transaction_fee: actual_min_max_fee_per_gas
                        .transaction_cost(gas_limit)
                        .unwrap_or(Wei::MAX),
                });
            }
```

**File:** rs/ethereum/cketh/minter/src/main.rs (L506-531)
```rust
                Err(ckerc20_burn_error) => {
                    let reimbursed_amount = match &ckerc20_burn_error {
                        LedgerBurnError::TemporarilyUnavailable { .. } => erc20_tx_fee, //don't penalize user in case of an error outside of their control
                        LedgerBurnError::InsufficientFunds { .. }
                        | LedgerBurnError::AmountTooLow { .. }
                        | LedgerBurnError::InsufficientAllowance { .. } => erc20_tx_fee
                            .checked_sub(CKETH_LEDGER_TRANSACTION_FEE)
                            .unwrap_or(Wei::ZERO),
                    };
                    if reimbursed_amount > Wei::ZERO {
                        let reimbursement_request = ReimbursementRequest {
                            ledger_burn_index: cketh_ledger_burn_index,
                            reimbursed_amount: reimbursed_amount.change_units(),
                            to: cketh_account.owner,
                            to_subaccount: cketh_account
                                .subaccount
                                .and_then(LedgerSubaccount::from_bytes),
                            transaction_hash: None,
                        };
                        mutate_state(|s| {
                            process_event(
                                s,
                                EventType::FailedErc20WithdrawalRequest(reimbursement_request),
                            );
                        });
                    }
```

**File:** rs/ethereum/cketh/minter/src/tx.rs (L610-616)
```rust
pub async fn lazy_refresh_gas_fee_estimate() -> Option<GasFeeEstimate> {
    const MAX_AGE_NS: u64 = 60_000_000_000_u64; //60 seconds

    async fn do_refresh() -> Option<GasFeeEstimate> {
        let _guard = match TimerGuard::new(TaskType::RefreshGasFeeEstimate) {
            Ok(guard) => guard,
            Err(e) => {
```

**File:** rs/ethereum/cketh/mainnet/minter_upgrade_2024_08_05.md (L16-16)
```markdown
* Fix a bug affecting ckERC20 withdrawals which were unnecessarily delayed as soon as the estimated transaction fees increased.
```

**File:** rs/bitcoin/ckbtc/mainnet/minter_upgrade_2025_06_27.md (L17-33)
```markdown
## Motivation

Upgrade the ckBTC minter to try to unblock three transactions ckBTC → BTC (withdrawals) that are currently stuck since
2025.06.21.

After analysis, see this
forum [**post**](https://forum.dfinity.org/t/ckbtc-a-canister-issued-bitcoin-twin-token-on-the-ic-1-1-backed-by-btc/17606/202)
for more details, the problem appears to be due to the following:

1. An extremely low fee per vbyte was chosen by the minter for those transactions, which prevented them from being mined
   in the first place. We currently don’t have a satisfying explanation for how this low median fee was computed and are
   also investigating the bitcoin canister. A stop-gap solution was introduced
   in [#5742](https://github.com/dfinity/ic/pull/5742), to ensure that the fee per vbyte computed by the minter is
   always at least 1.5 sats/vbyte (for Bitcoin Mainnet).
2. There is a deterministic panic occurring in the minter when it tries to resubmit those transactions, which explains
   why those transactions are currently stuck. This should be completely fixed
   by [#5713](https://github.com/dfinity/ic/pull/5713).
```

**File:** rs/ethereum/cketh/minter/tests/ckerc20.rs (L1047-1057)
```rust
        test_when_tx_fee(&mut increment_base_fee_per_gas)
            .expect_status(RetrieveEthStatus::Pending, WithdrawalStatus::Pending)
            .retrieve_latest_transaction_count(identity)
            .expect_status(RetrieveEthStatus::TxCreated);

        test_when_tx_fee(&mut double_and_increment_base_fee_per_gas)
            .expect_status(RetrieveEthStatus::Pending, WithdrawalStatus::Pending)
            .retrieve_latest_transaction_count(identity)
            .expect_status(RetrieveEthStatus::Pending)
            .expect_transaction_not_created();
    }
```
