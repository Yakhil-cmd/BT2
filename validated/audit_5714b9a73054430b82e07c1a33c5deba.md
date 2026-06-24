Audit Report

## Title
Stale ICP/XDR Exchange Rate Used Without Freshness Check in Cycle Minting — (`rs/nns/cmc/src/main.rs`)

## Summary
The `tokens_to_cycles()` function in the Cycles Minting Canister reads `state.icp_xdr_conversion_rate` and checks only that it is `Some`, with no check on the rate's age. If the Exchange Rate Canister is unavailable for an extended period (or is disabled via a `DivergedRate` governance proposal), the CMC silently continues minting cycles at the last-stored rate. An unprivileged user who observes that the stored rate is higher than the current market rate can convert ICP to cycles at the inflated stale rate, receiving more cycles than the ICP's current value justifies.

## Finding Description
`tokens_to_cycles()` at `rs/nns/cmc/src/main.rs` L1900–1923 reads `state.icp_xdr_conversion_rate` and only checks for `None`:

```rust
fn tokens_to_cycles(amount: Tokens) -> Result<Cycles, NotifyError> {
    with_state(|state| {
        let xdr_permyriad_per_icp = state
            .icp_xdr_conversion_rate
            .as_ref()
            .map(|rate| rate.xdr_permyriad_per_icp);
        match xdr_permyriad_per_icp {
            Some(xdr_permyriad_per_icp) => Ok(TokensToCycles { ... }.to_cycles(amount)),
            None => Err(...),
        }
    })
}
```

No check is made on `rate.timestamp_seconds` relative to the current canister time. All three minting paths — `process_mint_cycles` (L1965), `process_top_up` (L1991), and `process_create_canister` — call `tokens_to_cycles()` unconditionally.

The rate update mechanism (`do_set_icp_xdr_conversion_rate`, L1022–1039) only enforces that a new rate has a strictly greater timestamp than the current one; it does not enforce any maximum age at the point of use. The XRC heartbeat schedules refreshes every 5 minutes (`REFRESH_RATE_INTERVAL_SECONDS`, `exchange_rate_canister.rs` L16), but if the XRC is unavailable, the stored rate is never refreshed and minting is never blocked.

The update loop can be frozen in two ways without any unprivileged action:
1. A governance proposal with `DivergedRate` reason sets `UpdateExchangeRateState::Disabled` (`exchange_rate_canister.rs` L311–314), after which only another governance proposal can re-enable it.
2. The XRC canister fails persistently; the CMC retries every minute but the stored rate is never updated.

By contrast, the Governance canister's `should_refresh_xdr_rate()` (`rs/nns/governance/src/governance.rs` L6336–6348) explicitly enforces a 1-day maximum age before using the rate for node-provider reward calculations. No equivalent guard exists in the CMC for cycle minting.

The default state is initialized with `DEFAULT_ICP_XDR_CONVERSION_RATE_TIMESTAMP_SECONDS = 1_620_633_600` (May 2021) and `DEFAULT_XDR_PERMYRIAD_PER_ICP_CONVERSION_RATE = 1_000_000` (100 XDR/ICP) (`rs/nns/cmc/src/lib.rs` L33–34), meaning a fresh CMC deployment with no rate update would allow massive over-minting at ~20–30× the current market rate until governance intervenes.

## Impact Explanation
This constitutes illegal minting of cycles. An unprivileged user can receive significantly more cycles per ICP than the current market rate justifies, extracting value from the cycles economy. At the default rate (100 XDR/ICP vs. current ~3–5 XDR/ICP), a fresh or rate-frozen CMC would allow 20–30× over-minting. Even in a production scenario where the rate drifts by 2× during an XRC outage, the over-minting is material and repeatable by any user with ICP. This matches the **High** impact class: significant NNS/financial integration security impact with concrete protocol harm (illegal minting of in-scope chain assets).

## Likelihood Explanation
The XRC is a system canister subject to bugs, upgrades, and network partitions. The CMC retries every minute on failure but does not alert or block minting. The `DivergedRate` governance path is a documented, intentional feature that freezes the rate. During any such period — which could last hours to days — any unprivileged user who can call `notify_top_up` or `notify_mint_cycles` can exploit the stale rate. The attacker needs only to observe the on-chain stored rate (publicly readable) and compare it to the current ICP market price. No special privileges, social engineering, or key compromise is required once the precondition (stale rate) is met.

## Recommendation
Add a maximum-age check inside `tokens_to_cycles()` analogous to `should_refresh_xdr_rate()` in Governance. Before using the stored rate, compute `current_time - rate.timestamp_seconds` and return a `NotifyError` if it exceeds a defined threshold (e.g., 1 day). This mirrors the protection already present in the Governance canister and prevents the CMC from silently minting cycles at a stale rate. The threshold should be configurable via a governance proposal to allow operational flexibility.

## Proof of Concept
1. Deploy a CMC instance with `exchange_rate_canister_id = None` (or disable the XRC via a `DivergedRate` governance proposal).
2. Set the stored `icp_xdr_conversion_rate` to `xdr_permyriad_per_icp = 50_000` (5 XDR/ICP) with a timestamp from 48 hours ago.
3. Observe that ICP market price has dropped such that the correct rate is now `21_000` permyriad (2.1 XDR/ICP).
4. As an unprivileged user, send 1 ICP to the CMC subaccount and call `notify_top_up`.
5. `tokens_to_cycles()` reads `xdr_permyriad_per_icp = 50_000` (stale) and mints `50_000 / 10_000 * 1_000_000_000_000 = 5_000_000_000_000` cycles (5T cycles).
6. At the correct rate of `21_000` permyriad, the user should receive only 2.1T cycles.
7. The user has extracted ~2.9T extra cycles per ICP. This is repeatable with any amount of ICP for the duration of the XRC outage.
8. A deterministic integration test using PocketIC can reproduce this by: initializing CMC state with a stale rate timestamp, disabling the XRC client mock, and asserting that `notify_top_up` returns cycles exceeding the correct-rate calculation.