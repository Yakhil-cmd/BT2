Audit Report

## Title
CMC `burn_and_log` Intentionally Discards Burn Failures, Allowing Cycles Minting Without Corresponding ICP Destruction — (File: `rs/nns/cmc/src/main.rs`)

## Summary

The `burn_and_log` function in the Cycles Minting Canister is explicitly designed to swallow all ICP ledger errors and return `()`. All three notification paths (`process_mint_cycles`, `process_top_up`, `process_create_canister`) dispense value first, then call `burn_and_log` whose failure is silently ignored, and then seal the block index as permanently successful. If the ICP ledger is transiently unavailable between `fetch_transaction` and `burn_and_log`, cycles (or a canister) are dispensed while the backing ICP remains unburned and permanently stranded in the CMC's subaccount, breaking the ICP/cycles conservation invariant.

## Finding Description

`burn_and_log` (lines 2014–2049) has the signature `async fn burn_and_log(from_subaccount: Subaccount, amount: Tokens)` — it returns `()`, not `Result`. The developer comment at line 2014 explicitly states the intent: *"Burning doesn't return errors — we don't want to reject the transaction notification because then it could be retried."* The rationale is that if burn fails and an error is returned, the notification is not sealed, allowing a retry that would dispense cycles a second time for the same ICP payment.

However, the chosen design has the opposite failure mode. In `process_mint_cycles` (lines 1966–1973):

```rust
match do_mint_cycles(to_account, cycles, deposit_memo).await {
    Ok(deposit_result) => {
        burn_and_log(sub, amount).await;   // returns (), error silently dropped
        Ok(NotifyMintCyclesSuccess { ... })
    }
```

Identical patterns exist in `process_top_up` (lines 1999–2002) and `process_create_canister` (lines 1943–1946). In all three cases, the `Ok(...)` branch returns success unconditionally regardless of whether the ICP ledger call inside `burn_and_log` succeeded.

The caller then seals the block index (e.g., lines 1305–1312 for `notify_mint_cycles`):

```rust
state.blocks_notified.insert(
    block_index,
    NotificationStatus::NotifiedMint(result.clone()),
);
if is_transient_error(&result) {
    state.blocks_notified.remove(&block_index);
}
```

Because `process_mint_cycles` returns `Ok(...)` even when burn fails, `is_transient_error` evaluates to `false`, and the block index is permanently sealed as `NotifiedMint(Ok(...))`. No retry path exists.

**Exploit timing window:** `fetch_transaction` (step 1) and `burn_and_log` (step 3) both call the ICP ledger, but they are separated by the `do_mint_cycles` inter-canister call (step 2). If the ICP ledger becomes unavailable between steps 1 and 3 — e.g., mid-upgrade — step 1 succeeds, step 2 succeeds (cycles ledger is a separate canister), and step 3 fails silently. The result: cycles are credited, ICP is not burned, and the notification is permanently sealed.

## Impact Explanation

This is a conservation invariant violation: total cycles supply increases without a corresponding decrease in ICP supply. The stranded ICP sits in `Subaccount::from(&caller())` (or `&controller` / `&canister_id`) within the CMC, inaccessible to the user (no retry path) and not swept by any CMC mechanism. Repeated occurrences across ledger upgrade windows compound the imbalance. This constitutes illegal minting of cycles — a High-severity NNS/CMC financial integrity impact with concrete, irreversible protocol harm.

## Likelihood Explanation

NNS upgrade proposals for the ICP ledger are publicly visible on the NNS dashboard. An unprivileged user can monitor these proposals, pre-send ICP to their CMC subaccount, and call `notify_mint_cycles` timed to land after `fetch_transaction` succeeds but while the ledger upgrade is in progress. No special privilege is required. The window is narrow (seconds to tens of seconds per upgrade) but recurs with every ledger upgrade. The attacker does not need to cause the unavailability.

## Recommendation

1. **Propagate burn failures.** Change `burn_and_log` to return `Result<(), String>` and propagate errors. If burn fails, do not seal the notification as `Ok`; instead treat it as a transient error so the block index is removed and the user can retry.

2. **Preferred: burn before dispensing.** Burn the ICP first; only if the burn succeeds, proceed to mint cycles / create canister / top up. This eliminates the window entirely and matches standard acquire-before-dispense ordering.

3. **If dispensing-first is kept**, at minimum record the notification as a transient failure when `burn_and_log` fails, so the user can retry and the ICP is not permanently stranded.

## Proof of Concept

1. User transfers `N` ICP to `AccountIdentifier(CMC_ID, Subaccount::from(&caller))` with `memo = MEMO_MINT_CYCLES`.
2. Monitor NNS dashboard for an ICP ledger upgrade proposal that is about to execute.
3. Call `notify_mint_cycles { block_index, to_subaccount: None, deposit_memo: None }` timed so that `fetch_transaction` completes before the ledger stops, and `burn_and_log` executes while the ledger is stopped/upgrading.
4. `do_mint_cycles` succeeds → cycles credited to user on cycles ledger.
5. `burn_and_log` fails (ledger rejects call) → error dropped, `Ok(NotifyMintCyclesSuccess { ... })` returned.
6. CMC seals `NotificationStatus::NotifiedMint(Ok(...))` for the block index.
7. **Result:** User holds cycles worth `N` ICP. The `N` ICP sits unburned in the CMC subaccount. Block index is permanently sealed; no refund or retry is possible. ICP supply and cycles supply are out of balance by `N` ICP.

A deterministic integration test can reproduce this by mocking the ICP ledger to return `TemporarilyUnavailable` on the `send_pb` call while allowing `fetch_transaction` to succeed, then asserting that the cycles ledger balance increased while the CMC subaccount ICP balance is non-zero and the block index is sealed as `NotifiedMint(Ok(...))`.