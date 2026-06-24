Audit Report

## Title
Unchecked Return Value of ICP Ledger Burn Call in CMC Silently Locks ICP and Violates Conservation - (File: rs/nns/cmc/src/main.rs)

## Summary
The `burn_and_log` function in the Cycles Minting Canister unconditionally returns `()` regardless of whether the ICP ledger burn call succeeds or fails. When the burn fails transiently, the notification is permanently recorded as successfully processed, the block index is consumed, and the ICP remains locked in the CMC's subaccount with no retry or recovery path. This violates ICP supply conservation: cycles are minted without the corresponding ICP being destroyed.

## Finding Description
`burn_and_log` (lines 2014–2048) issues a `send_pb` call to the ICP ledger to burn the deposited ICP by sending it to the minting account. On error, it logs and returns `()`:

```rust
// rs/nns/cmc/src/main.rs:2042-2047
match res {
    Ok(block) => print(format!("{msg} done in block {block}.")),
    Err((code, err)) => {
        let code = code as i32;
        print(format!("{msg} failed with code {code}: {err:?}"))
    }
}
```

All three callers — `process_top_up` (line 2001), `process_create_canister` (line 1945), and `process_mint_cycles` (line 1968) — unconditionally return `Ok(...)` after `burn_and_log` returns, regardless of burn outcome. After `process_top_up` returns `Ok(cycles)`, the caller at lines 1214–1222 permanently records `NotificationStatus::NotifiedTopUp(Ok(cycles))` for the block index. The `is_transient_error` guard at line 1219 only removes the entry for transient errors in the *outer* `process_top_up` result — a burn failure is invisible to this guard because `burn_and_log` always returns `()`. The block index is therefore consumed and cannot be re-notified. No heartbeat, sweep, or retry mechanism exists for failed burns anywhere in the file.

The design comment at line 2015 explicitly acknowledges the trade-off: *"Burning doesn't return errors - we don't want to reject the transaction notification because then it could be retried."* The intent is correct (prevent double-minting), but the consequence of a transient failure is permanent ICP lock with no recovery path.

## Impact Explanation
This is a concrete ICP supply conservation violation and permanent loss of protocol funds. Cycles are minted (the deposit to the canister or cycles ledger succeeds), but the corresponding ICP is not burned. The ICP remains in the CMC's subaccount keyed by `Subaccount::from(&canister_id)` (or controller/account). Only the CMC itself can spend from its own subaccounts, and no sweep or retry endpoint exists. The locked ICP is permanently inaccessible and inflates the circulating ICP supply relative to the minted cycles. This matches the High impact category: significant NNS/ledger/financial integrity impact with concrete and permanent protocol harm. Accumulated across multiple ledger upgrade windows, the total locked ICP can grow unboundedly.

## Likelihood Explanation
The ICP ledger is stopped during NNS-governed upgrades, which occur regularly on mainnet. Any `notify_top_up`, `notify_create_canister`, or `notify_mint_cycles` call whose cycles deposit completes successfully but whose subsequent `burn_and_log` call hits the ledger during its stopped/upgrading window will trigger the silent failure. The user does not need to control or cause the ledger failure — they only need to submit a valid notification during a known upgrade window. This is a realistic, repeatable operational condition, not a theoretical one.

## Recommendation
Track failed burns in persistent canister state (e.g., a `Vec<(Subaccount, Tokens)>` of pending burns). Process this queue in the existing `canister_heartbeat` or a dedicated timer. Alternatively, expose a permissionless `retry_burn(subaccount, amount)` endpoint that re-attempts the ledger call after the ledger recovers. The current approach of not propagating errors to the caller is correct for preventing double-minting; the missing piece is ensuring eventual burn completion through a separate, idempotent retry path.

## Proof of Concept
1. User sends N ICP to `AccountIdentifier::new(CMC_ID, Some(Subaccount::from(&canister_id)))`.
2. User calls `notify_top_up { block_index, canister_id }`.
3. CMC calls `deposit_cycles` → management canister deposits cycles to `canister_id` successfully.
4. CMC calls `burn_and_log(Subaccount::from(&canister_id), amount)`.
5. The ICP ledger is stopped for an NNS upgrade; `call_protobuf` returns `Err(CanisterStopped, ...)`.
6. `burn_and_log` logs the error and returns `()`.
7. `process_top_up` returns `Ok(cycles)`.
8. `notify_top_up` records `NotificationStatus::NotifiedTopUp(Ok(cycles))` for `block_index`.
9. User received cycles. N ICP remains in the CMC subaccount, unburned, permanently locked.
10. Any subsequent `notify_top_up` with the same `block_index` returns the cached `Ok(cycles)` without attempting another burn.
11. To confirm: write a PocketIC integration test that (a) sends ICP to the CMC subaccount, (b) pauses/stops the ledger canister, (c) calls `notify_top_up`, (d) resumes the ledger, and (e) asserts that the CMC subaccount balance is non-zero and the ledger total supply has not decreased by the expected amount.