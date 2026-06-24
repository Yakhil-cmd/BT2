Audit Report

## Title
Missing Reimbursement for `AmountTooLow` Finalized Withdrawal Requests Causes Permanent Loss of User ckBTC - (`rs/bitcoin/ckbtc/minter/src/lib.rs`)

## Summary

When a ckBTC withdrawal request is accepted, the user's ckBTC is burned immediately. If Bitcoin network fees rise before the minter batches the request into a transaction, `build_unsigned_transaction` returns `BuildTxError::AmountTooLow`. The minter finalizes the request with `FinalizedStatus::AmountTooLow` but never schedules a reimbursement, leaving the user with neither BTC nor ckBTC. The identical omission applies to the `BuildTxError::DustOutput` branch.

## Finding Description

**Burn happens at acceptance time, before fee validation:**
In `retrieve_btc_with_approval`, `burn_ckbtcs_icrc2` is called at line 314 to burn the user's ckBTC, and only then is the request enqueued in `pending_retrieve_btc_requests`. [1](#0-0) 

**`InvalidTransaction` branch correctly reimburses:**
When `build_unsigned_transaction` returns `BuildTxError::InvalidTransaction`, `reimburse_canceled_requests` is called, which schedules a `ScheduleWithdrawalReimbursement` event and eventually mints ckBTC back to the user. [2](#0-1) 

**`AmountTooLow` branch silently discards the request with no reimbursement:**
When `BuildTxError::AmountTooLow` is returned, the code only calls `remove_retrieve_btc_request` with `FinalizedStatus::AmountTooLow`. No call to `reimburse_canceled_requests` or any equivalent is made. [3](#0-2) 

The same omission exists in the `DustOutput` branch: [4](#0-3) 

**`remove_retrieve_btc_request` has no reimbursement logic:**
It only records a `RemovedRetrieveBtcRequest` event and pushes to `finalized_requests`. No reimbursement is enqueued. [5](#0-4) 

**`FinalizedStatus::AmountTooLow` is a terminal state with no reimbursement path:**
The enum has only `AmountTooLow` and `Confirmed` variants; there is no associated reimbursement field or successor state. [6](#0-5) 

**`WithdrawalReimbursementReason` has no variant for fee-related failures:**
Only `InvalidTransaction` is defined; there is no `AmountTooLow` or `FeeTooHigh` variant to pass to the reimbursement machinery. [7](#0-6) 

**The reimbursement machinery exists but is never invoked for this case:**
`reimburse_withdrawals` correctly mints ckBTC back for entries in `pending_withdrawal_reimbursements`, but that map is never populated for `AmountTooLow` requests. [8](#0-7) 

## Impact Explanation

This is a **High** severity finding. It constitutes a concrete, permanent loss of user ckBTC funds in the ckBTC chain-fusion system — an in-scope financial integration. Any user whose pending withdrawal request is caught by a Bitcoin fee spike loses their burned ckBTC with no recovery path available through any public endpoint. The `retrieve_btc_status_v2` query returns a terminal `AmountTooLow` status with no `WillReimburse` or `Reimbursed` successor, confirming the funds are unrecoverable. This matches the allowed impact: *"Significant Chain Fusion, ck-token, ledger … security impact with concrete user or protocol harm."*

## Likelihood Explanation

Bitcoin fee spikes are a recurring, externally-driven, and unpredictable event. The `fee_based_retrieve_btc_min_amount` threshold is set at canister initialization/upgrade time and does not dynamically track the current fee market. During periods of high mempool congestion (e.g., Ordinals/Runes inscription waves), fees can increase by an order of magnitude within hours. Any user whose request sits in `pending_retrieve_btc_requests` across such a spike is at risk. No special privileges are required — any unprivileged user who submits a valid withdrawal is exposed. The scenario is a normal operational condition, not a contrived edge case.

## Recommendation

Apply the same reimbursement pattern used for `BuildTxError::InvalidTransaction` to both the `AmountTooLow` and `DustOutput` branches:

1. Add a new variant (e.g., `AmountTooLow`) to `WithdrawalReimbursementReason` in `rs/bitcoin/ckbtc/minter/src/reimbursement/mod.rs`.
2. In the `BuildTxError::AmountTooLow` branch (`lib.rs` L412–434), replace the bare `remove_retrieve_btc_request` loop with a call to `reimburse_canceled_requests(s, batch, WithdrawalReimbursementReason::AmountTooLow, reimbursement_fee, runtime)`.
3. Apply the same change to the matching request in the `BuildTxError::DustOutput` branch (`lib.rs` L446–453).
4. Ensure `reimburse_canceled_requests` records a `ScheduleWithdrawalReimbursement` event so that the periodic `reimburse_withdrawals` task mints ckBTC back to the user's `reimbursement_account`.

## Proof of Concept

1. User calls `retrieve_btc_with_approval` with amount `X` where `X >= fee_based_retrieve_btc_min_amount`. `burn_ckbtcs_icrc2` burns `X` ckBTC immediately (L314 in `retrieve_btc.rs`).
2. The request enters `pending_retrieve_btc_requests`.
3. Bitcoin network fees spike. The minter's fee estimator now computes `fee > X`.
4. `submit_pending_requests` is called. `build_unsigned_transaction` returns `BuildTxError::AmountTooLow`.
5. The minter executes the `AmountTooLow` branch (L412–434 in `lib.rs`): `remove_retrieve_btc_request(s, request, FinalizedStatus::AmountTooLow, runtime)` is called for each request in the batch. No reimbursement is scheduled.
6. `retrieve_btc_status_v2(block_index)` returns `RetrieveBtcStatusV2::AmountTooLow` permanently (L913 in `state.rs`).
7. The user's ckBTC is burned; no BTC was sent; no ckBTC is minted back. Funds are permanently lost.

A deterministic integration test can reproduce this by: initializing the minter with a low `retrieve_btc_min_amount`, submitting a withdrawal, then calling `submit_pending_requests` with a mock fee estimator returning a fee higher than the withdrawal amount, and asserting that `pending_withdrawal_reimbursements` is non-empty (it will be empty, confirming the bug).

### Citations

**File:** rs/bitcoin/ckbtc/minter/src/updates/retrieve_btc.rs (L314-333)
```rust
    let block_index = burn_ckbtcs_icrc2(
        caller_account,
        args.amount,
        crate::memo::encode(&burn_memo_icrc2).into(),
    )
    .await?;

    let request = RetrieveBtcRequest {
        amount: args.amount,
        address: parsed_address,
        block_index,
        received_at: ic_cdk::api::time(),
        kyt_provider: None,
        reimbursement_account: Some(Account {
            owner: caller,
            subaccount: args.from_subaccount,
        }),
    };

    mutate_state(|s| state::audit::accept_retrieve_btc_request(s, request, runtime));
```

**File:** rs/bitcoin/ckbtc/minter/src/lib.rs (L400-411)
```rust
            Err(BuildTxError::InvalidTransaction(err)) => {
                log!(
                    Priority::Info,
                    "[submit_pending_requests]: error in building transaction ({:?})",
                    err
                );
                let reason = reimbursement::WithdrawalReimbursementReason::InvalidTransaction(err);
                let reimbursement_fee = fee_estimator
                    .reimbursement_fee_for_pending_withdrawal_requests(batch.len() as u64);
                reimburse_canceled_requests(s, batch, reason, reimbursement_fee, runtime);
                None
            }
```

**File:** rs/bitcoin/ckbtc/minter/src/lib.rs (L412-434)
```rust
            Err(BuildTxError::AmountTooLow) => {
                log!(
                    Priority::Info,
                    "[submit_pending_requests]: dropping requests for total BTC amount {} to addresses {} (too low to cover the fees)",
                    tx::DisplayAmount(batch.iter().map(|req| req.amount).sum::<u64>()),
                    batch
                        .iter()
                        .map(|req| req.address.display(s.btc_network))
                        .collect::<Vec<_>>()
                        .join(",")
                );

                // There is no point in retrying the request because the
                // amount is too low.
                for request in batch {
                    state::audit::remove_retrieve_btc_request(
                        s,
                        request,
                        state::FinalizedStatus::AmountTooLow,
                        runtime,
                    );
                }
                None
```

**File:** rs/bitcoin/ckbtc/minter/src/lib.rs (L436-468)
```rust
            Err(BuildTxError::DustOutput { address, amount }) => {
                log!(
                    Priority::Info,
                    "[submit_pending_requests]: dropping a request for BTC amount {} to {} (too low to cover the fees)",
                    tx::DisplayAmount(amount),
                    address.display(s.btc_network)
                );

                let mut requests_to_put_back = BTreeSet::new();
                for request in batch {
                    if request.address == address && request.amount == amount {
                        // Finalize the request that we cannot fulfill.
                        state::audit::remove_retrieve_btc_request(
                            s,
                            request,
                            state::FinalizedStatus::AmountTooLow,
                            runtime,
                        );
                    } else {
                        // Keep the rest of the requests in the batch, we will
                        // try to build a new transaction on the next iteration.
                        requests_to_put_back.insert(request);
                    }
                }

                s.push_from_in_flight_to_pending_requests(
                    state::SubmittedWithdrawalRequests::ToConfirm {
                        requests: requests_to_put_back,
                    },
                );

                None
            }
```

**File:** rs/bitcoin/ckbtc/minter/src/state/audit.rs (L67-84)
```rust
pub fn remove_retrieve_btc_request<R: CanisterRuntime>(
    state: &mut CkBtcMinterState,
    request: RetrieveBtcRequest,
    status: FinalizedStatus,
    runtime: &R,
) {
    record_event(
        EventType::RemovedRetrieveBtcRequest {
            block_index: request.block_index,
        },
        runtime,
    );

    state.push_finalized_request(FinalizedBtcRequest {
        request: request.into(),
        state: status,
    });
}
```

**File:** rs/bitcoin/ckbtc/minter/src/state.rs (L259-267)
```rust
pub enum FinalizedStatus {
    /// The request amount was to low to cover the fees.
    AmountTooLow,
    /// The transaction that retrieves BTC got enough confirmations.
    Confirmed {
        /// The witness transaction identifier of the transaction.
        txid: Txid,
    },
}
```

**File:** rs/bitcoin/ckbtc/minter/src/reimbursement/mod.rs (L39-55)
```rust
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, candid::CandidType)]
pub enum WithdrawalReimbursementReason {
    #[serde(rename = "invalid_transaction")]
    InvalidTransaction(InvalidTransactionError),
}

#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, candid::CandidType)]
pub enum InvalidTransactionError {
    /// The transaction contains too many inputs.
    /// If such a transaction were signed, there is a risk that the resulting transaction will have a size of
    /// over 100k vbytes and therefore be *non-standard*.
    #[serde(rename = "too_many_inputs")]
    TooManyInputs {
        num_inputs: usize,
        max_num_inputs: usize,
    },
}
```

**File:** rs/bitcoin/ckbtc/minter/src/reimbursement/mod.rs (L58-116)
```rust
pub async fn reimburse_withdrawals<R: CanisterRuntime>(runtime: &R) {
    if state::read_state(|s| s.pending_withdrawal_reimbursements.is_empty()) {
        return;
    }
    let pending_reimbursements = state::read_state(|s| s.pending_withdrawal_reimbursements.clone());
    let mut error_count = 0;
    for (burn_index, reimbursement) in pending_reimbursements {
        // Ensure that even if we were to panic in the callback, after having contacted the ledger to mint the tokens,
        // this reimbursement request will not be processed again.
        let prevent_double_minting_guard = scopeguard::guard(burn_index, |index| {
            state::mutate_state(|s| {
                state::audit::quarantine_withdrawal_reimbursement(s, index, runtime)
            });
        });
        let memo = MintMemo::ReimburseWithdrawal {
            withdrawal_id: burn_index,
        };
        match runtime
            .mint_ckbtc(
                reimbursement.amount,
                reimbursement.account,
                Memo::from(crate::memo::encode(&memo)),
            )
            .await
        {
            Ok(mint_index) => {
                log!(
                    Priority::Debug,
                    "[reimburse_withdrawals]: Successfully reimbursed {:?} at mint block index {}",
                    reimbursement,
                    mint_index
                );
                state::mutate_state(|s| {
                    state::audit::reimburse_withdrawal_completed(s, burn_index, mint_index, runtime)
                });
            }
            Err(err) => {
                log!(
                    Priority::Info,
                    "[reimburse_withdrawals]: Failed to reimburse {:?}: {:?}. Will retry later",
                    reimbursement,
                    err
                );
                error_count += 1;
            }
        }
        // Defuse the guard. Note that in case of a panic in the callback (either before or after this point)
        // the defuse will not be effective (due to state rollback), and the guard that was
        // setup before the `mint_ckbtc` async call will be invoked.
        scopeguard::ScopeGuard::into_inner(prevent_double_minting_guard);
    }

    if error_count > 0 {
        log!(
            Priority::Info,
            "[reimburse_withdrawals] Failed to reimburse {error_count} withdrawal requests, retrying later."
        );
    }
}
```
