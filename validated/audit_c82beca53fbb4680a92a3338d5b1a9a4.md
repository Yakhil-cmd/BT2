Audit Report

## Title
Missing Rate Staleness Check at Point of Use Enables Cycles Over-Minting with Stale ICP/XDR Rate - (File: `rs/nns/cmc/src/main.rs`)

## Summary
The `tokens_to_cycles()` function in the Cycles Minting Canister reads `state.icp_xdr_conversion_rate` and uses only `xdr_permyriad_per_icp`, never comparing `timestamp_seconds` against the current time. If the Exchange Rate Canister (XRC) is persistently unavailable, the stored rate ages indefinitely with no upper-bound guard, and any unprivileged caller of `notify_top_up`, `notify_mint_cycles`, or `notify_create_canister` will receive cycles computed at the stale (potentially much higher) rate, constituting illegal cycles minting in excess of the ICP value burned.

## Finding Description
`tokens_to_cycles()` at `rs/nns/cmc/src/main.rs:1900–1923` extracts only `xdr_permyriad_per_icp` from the stored rate struct; `timestamp_seconds` is never read or compared against `now`:

```rust
fn tokens_to_cycles(amount: Tokens) -> Result<Cycles, NotifyError> {
    with_state(|state| {
        let xdr_permyriad_per_icp = state
            .icp_xdr_conversion_rate
            .as_ref()
            .map(|rate| rate.xdr_permyriad_per_icp);  // timestamp_seconds silently dropped
        ...
    })
}
```

`process_top_up()` at line 1991 calls `tokens_to_cycles(amount)?` with no intervening age check. The same is true for `process_mint_cycles` (called from `notify_mint_cycles` at line 1303) and the create-canister path.

`validate_exchange_rate()` in `rs/nervous_system/clients/src/exchange_rate_canister_client.rs:111–129` only validates source counts (`base_asset_num_received_rates`, `quote_asset_num_received_rates`); it has no timestamp or age parameter.

`do_set_icp_xdr_conversion_rate()` at `rs/nns/cmc/src/main.rs:1022–1030` enforces only monotonically increasing timestamps (new rate must be strictly newer than the stored one), not that the rate is recent relative to wall-clock time.

The heartbeat-driven refresh in `rs/nns/cmc/src/exchange_rate_canister.rs` targets a `REFRESH_RATE_INTERVAL_SECONDS` of 5 minutes (line 16). When the XRC call fails, the guard schedules a retry one minute later (lines 153–160), but the stored rate is never updated during the failure window. There is no code path that blocks minting when the stored rate's age exceeds any threshold.

## Impact Explanation
If the XRC is unavailable for an extended period (hours to days) and the real ICP/XDR market rate falls during that window, every caller of `notify_top_up` or `notify_mint_cycles` receives cycles computed at the frozen, higher rate. For example, a 50% ICP price drop while the rate is frozen yields 2× the correct cycle amount per ICP burned. This is illegal minting of cycles — the protocol mints more cycles than the ICP value destroyed warrants — directly violating the economic invariant of the CMC. This matches the allowed impact: **High ($2,000–$10,000): Significant XRC/NNS infrastructure security impact with concrete user or protocol harm**, with constraints (requires external XRC unavailability and concurrent ICP price movement).

## Likelihood Explanation
The XRC is a system canister; subnet upgrades, replica bugs, or transient network partitions can render it unavailable for minutes to hours. The CMC's retry loop (every minute on failure) keeps the state machine alive but never updates the stored rate. The attacker requires no special privilege: any principal can send ICP to the CMC's subaccount and call `notify_top_up` or `notify_mint_cycles`. The attacker does not need to cause XRC unavailability — they only need to observe it (e.g., by monitoring CMC metrics or the XRC canister status) and time their ICP transfer accordingly. The exploit is repeatable for the entire duration of the unavailability window.

The governance-disabled (`DivergedRate`) scenario requires a governance majority and is excluded from this finding per scope rules; the XRC unavailability scenario alone is sufficient.

## Recommendation
1. In `tokens_to_cycles()`, read `rate.timestamp_seconds` and compare it against `now_seconds()`; return `NotifyError::Other` if the age exceeds a defined maximum (e.g., 30–60 minutes).
2. Optionally extend `validate_exchange_rate()` to accept a `now_seconds: u64` parameter and reject rates older than the staleness threshold at ingestion time.
3. Expose a metric or certified variable for the age of the current stored rate so monitoring can alert before the window becomes exploitable.

## Proof of Concept
1. Deploy the NNS locally (PocketIC or local replica) with CMC and a mock XRC.
2. Set the mock XRC to return errors on all calls, simulating persistent unavailability.
3. Advance the test clock by, e.g., 2 hours; confirm via CMC state that `icp_xdr_conversion_rate.timestamp_seconds` is now 2 hours old.
4. Simulate an ICP price drop by noting the frozen rate is, say, 2× the "current" rate.
5. Send ICP to the CMC's top-up subaccount and call `notify_top_up` from an unprivileged principal.
6. Assert that the returned `Cycles` value equals `amount * frozen_rate`, not `amount * current_rate`, confirming over-minting.
7. Verify that `total_cycles_minted` increases by an amount inconsistent with the current market value of the burned ICP.