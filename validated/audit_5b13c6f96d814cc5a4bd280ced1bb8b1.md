All three cited code locations are confirmed in the repository. The `assert!(fee > 0, "withdraw_fee is zero")` is present at line 1053 of `state.rs`, the `withdrawal_fee: Some(total_fee)` construction is at lines 1003-1014 of `lib.rs`, and the upgrade proposal at `rs/bitcoin/ckbtc/mainnet/minter_upgrade_2025_06_27.md` explicitly confirms the deterministic panic and the mainnet incident. The call chain `finalize_requests` → `confirm_transaction` → `state::audit::confirm_transaction` → `state.finalize_transaction` is verified. The vulnerability is real, in-scope, and confirmed by a mainnet incident.

Audit Report

## Title
ckBTC Minter `finalize_transaction` Hard `assert!` on Zero `withdrawal_fee` Permanently DoS-es BTC Withdrawals - (File: rs/bitcoin/ckbtc/minter/src/state.rs)

## Summary
The `finalize_transaction` function in the ckBTC minter contains a hard `assert!(fee > 0, "withdraw_fee is zero")` in the `ToCancel` branch. When a cancellation replacement transaction carries a zero-valued `withdrawal_fee` — which occurred on mainnet due to an anomalously low fee-per-vbyte estimate — the minter's heartbeat-driven finalization loop traps deterministically on every invocation. Because the trap rolls back the heartbeat message without removing the stuck transaction from state, every subsequent heartbeat re-enters the same path and traps again, permanently blocking all pending ckBTC → BTC withdrawals until a canister upgrade is deployed.

## Finding Description
In `rs/bitcoin/ckbtc/minter/src/state.rs` at lines 1049–1053, `finalize_transaction` handles the `ToCancel` variant as follows:

```rust
SubmittedWithdrawalRequests::ToCancel { requests, reason } => {
    let requests = requests.into_iter().collect::<BTreeSet<_>>();
    let fee = finalized_tx.withdrawal_fee.unwrap_or_default();
    let fee = fee.bitcoin_fee + fee.minter_fee;
    assert!(fee > 0, "withdraw_fee is zero");
```

`withdrawal_fee` is typed `Option<WithdrawalFee>`. `unwrap_or_default()` on `None` yields `WithdrawalFee { bitcoin_fee: 0, minter_fee: 0 }`, making `fee = 0` and firing the assert. Even when `withdrawal_fee` is `Some(...)`, if `build_unsigned_transaction_from_inputs` computes a near-zero fee due to an extremely low fee-per-vbyte, `total_fee` can be `WithdrawalFee { bitcoin_fee: 0, minter_fee: 0 }`, which is then stored as `withdrawal_fee: Some(total_fee)` in the replacement transaction at `rs/bitcoin/ckbtc/minter/src/lib.rs` lines 1003–1014.

The call chain is: heartbeat → `finalize_requests` → `process_maybe_finalized_transactions` → `confirm_transaction` (lib.rs:331) → `state::audit::confirm_transaction` (audit.rs:108–114) → `state.finalize_transaction`. In the IC execution model, a trap in a heartbeat rolls back the message but leaves the canister state unchanged. The stuck transaction remains in `submitted_transactions` or `stuck_transactions`, so every subsequent heartbeat re-enters the same path and traps again. No other code path can remove the stuck transaction or advance the finalization queue.

The mainnet upgrade proposal at `rs/bitcoin/ckbtc/mainnet/minter_upgrade_2025_06_27.md` lines 31–33 explicitly confirms: *"There is a deterministic panic occurring in the minter when it tries to resubmit those transactions, which explains why those transactions are currently stuck. This should be completely fixed by #5713."*

## Impact Explanation
This is a **High** severity finding matching the allowed impact: *"Application/platform-level DoS, crash, consensus blocking, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS"* and *"Significant Chain Fusion, ck-token, ledger... security impact with concrete user or protocol harm."*

All pending ckBTC → BTC withdrawal requests are blocked for the duration of the stuck state. User funds are not lost but are completely inaccessible (locked in the minter) until a governance-approved canister upgrade is deployed. The mainnet incident on 2025-06-21 confirmed three real user withdrawals were stuck. The minter's heartbeat is the sole mechanism for finalizing submitted transactions; its permanent trapping halts the entire withdrawal pipeline, not just the affected transaction.

## Likelihood Explanation
The condition is reachable without any privileged access. A normal user submitting a `retrieve_btc` request is sufficient to start the chain of events. The critical precondition — the minter's fee estimator returning an anomalously low fee per vbyte — is an internal minter behavior that occurred on mainnet without any attacker involvement. Once a `ToCancel` replacement transaction is constructed with `total_fee = 0`, the trap is deterministic and repeating. The mainnet incident proves this is not theoretical: it occurred with real user funds on 2025-06-21 and required an emergency upgrade proposal to resolve.

## Recommendation
Replace the hard `assert!` with a graceful error path that logs the anomaly and skips or reimburses the affected request without trapping:

```rust
if fee == 0 {
    log!(Priority::Error,
         "withdraw_fee is zero for cancellation tx {txid}; skipping");
    // reimburse or mark as failed without panicking
    return None;
}
```

Additionally, `resubmit_transactions` in `lib.rs` should validate that `total_fee.bitcoin_fee + total_fee.minter_fee > 0` before constructing a `ToCancel` replacement transaction, preventing the zero-fee value from ever being stored in state.

## Proof of Concept
1. Submit a `retrieve_btc` request when the minter's fee estimator returns a near-zero fee per vbyte (as occurred on mainnet 2025-06-21).
2. The submitted transaction is not mined (stuck in mempool or evicted).
3. Wait for `MIN_RESUBMISSION_DELAY`; the minter calls `resubmit_transactions`.
4. `build_unsigned_transaction_from_inputs` computes `total_fee = WithdrawalFee { bitcoin_fee: 0, minter_fee: 0 }` due to the near-zero fee rate.
5. A `ToCancel` replacement transaction is stored with `withdrawal_fee: Some(WithdrawalFee { bitcoin_fee: 0, minter_fee: 0 })`.
6. The Bitcoin network mines the cancellation transaction; the heartbeat calls `finalize_transaction`.
7. `assert!(fee > 0, "withdraw_fee is zero")` fires at `state.rs:1053`; the heartbeat traps.
8. Every subsequent heartbeat traps on the same path; no withdrawals can be finalized.

A deterministic integration test can reproduce this by: (a) setting fee percentiles to all-zero in `CkBtcSetup`, (b) submitting a `retrieve_btc` request, (c) advancing time past `MIN_RESUBMISSION_DELAY`, (d) triggering the `ToCancel` resubmission path, and (e) confirming the replacement transaction — the `finalize_transaction` call will panic.