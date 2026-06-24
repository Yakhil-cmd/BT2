Audit Report

## Title
Stale ICP/XDR Exchange Rate Used Without Age Validation in Cycle Minting - (File: rs/nns/cmc/src/main.rs)

## Summary
The `tokens_to_cycles` function in the Cycles Minting Canister reads `state.icp_xdr_conversion_rate` and uses it unconditionally with no check on the age of the stored rate. When the Exchange Rate Canister (XRC) is unavailable, the CMC retains the last known rate indefinitely while continuing to serve cycle minting requests. An unprivileged user can exploit a stale (inflated) rate by purchasing ICP at the current depressed market price and converting it to cycles at the outdated rate, minting more cycles than the ICP burned is worth at current market value.

## Finding Description
`tokens_to_cycles` (rs/nns/cmc/src/main.rs, L1900–1923) extracts only `xdr_permyriad_per_icp` from the stored rate and never consults `timestamp_seconds`:

```rust
fn tokens_to_cycles(amount: Tokens) -> Result<Cycles, NotifyError> {
    with_state(|state| {
        let xdr_permyriad_per_icp = state
            .icp_xdr_conversion_rate
            .as_ref()
            .map(|rate| rate.xdr_permyriad_per_icp);  // timestamp ignored
        ...
    })
}
```

The rate is refreshed every `REFRESH_RATE_INTERVAL_SECONDS` (5 minutes, rs/nns/cmc/src/exchange_rate_canister.rs L15–16). On XRC failure, `update_exchange_rate` returns `UpdateExchangeRateError::FailedToRetrieveRate` (L270–274) and the guard reschedules a retry at the next minute (L153–160), but the stored rate is left unchanged. `do_set_icp_xdr_conversion_rate` (rs/nns/cmc/src/main.rs L1022–1033) only enforces monotonically increasing timestamps on incoming rates; it imposes no upper bound on how old the current rate may be when used for conversions. `validate_exchange_rate` (rs/nervous_system/clients/src/exchange_rate_canister_client.rs L110–129) only checks source counts, not rate age. The `IcpXdrConversionRate` struct carries `timestamp_seconds` (rs/nns/cmc/src/lib.rs L487–497) that is never consulted at conversion time. The circuit breaker (`UpdateExchangeRateState::Disabled`) requires a governance proposal with `DivergedRate` reason (rs/nns/cmc/src/exchange_rate_canister.rs L311–315) and is not triggered automatically by staleness.

Exploit path:
1. XRC begins returning errors (e.g., `CryptoBaseAssetNotFound`, `StablecoinRateTooFewRates`). CMC retries every minute but the stored rate freezes.
2. ICP market price drops while the CMC rate remains at the pre-outage value.
3. Attacker buys ICP at the depressed market price.
4. Attacker calls `notify_top_up` or `notify_mint_cycles` (both unprivileged). `process_top_up` (L1985–2011) calls `tokens_to_cycles` which uses the stale rate.
5. Attacker receives cycles computed at the inflated stale rate — more cycles than the ICP burned is worth at current market price.

## Impact Explanation
This constitutes illegal minting of cycles: the protocol issues cycles in excess of the real economic value of the ICP burned, inflating the cycle supply. Cycles are the computational currency of the IC; systematic over-issuance degrades the economic integrity of the protocol. The per-hour `base_cycles_limit` provides partial mitigation but does not eliminate the issue — over a sustained XRC outage, cumulative over-minting can be significant. This matches the allowed impact: **High ($2,000–$10,000) — Significant XRC/NNS infrastructure security impact with concrete protocol harm**, and potentially **Critical** if the rate divergence and outage duration are large enough to exceed $1M in over-minted cycle value.

## Likelihood Explanation
XRC failures are a documented and explicitly tested scenario in the codebase (tests for `CryptoBaseAssetNotFound`, `StablecoinRateTooFewRates`, insufficient source counts exist in rs/nns/cmc/src/exchange_rate_canister.rs). The entry point (`notify_top_up`) requires no special privileges — any user with an ICP ledger account can call it. ICP price can move materially in minutes. The attacker needs only to monitor XRC failure state (observable on-chain via the `cmc_update_exchange_rate_canister_state` metric or by querying the CMC) and ICP market price simultaneously, which is straightforward.

## Recommendation
1. **Add a staleness guard in `tokens_to_cycles`**: compare `rate.timestamp_seconds` against the current time and return an error (e.g., `NotifyError::Other` with a descriptive message) if the rate is older than a configurable threshold (e.g., 30 minutes).
2. **Automatic circuit breaker**: if the rate has not been successfully refreshed within N minutes, automatically set `update_exchange_rate_canister_state` to `Disabled` (pausing cycle minting) without requiring a governance proposal.
3. **Alert on rate age**: the existing `cmc_icp_xdr_conversion_rate_timestamp_seconds` metric (rs/nns/cmc/src/main.rs L2493–2501) already exposes the rate timestamp; add a monitoring alert so operators are notified before the rate becomes dangerously stale.

## Proof of Concept
A deterministic integration test using PocketIC or the existing test harness in rs/nns/cmc/src/exchange_rate_canister.rs:

1. Initialize CMC state with `icp_xdr_conversion_rate = Some(IcpXdrConversionRate { timestamp_seconds: T, xdr_permyriad_per_icp: 50_000 })`.
2. Configure the mock XRC client to return `Err(GetExchangeRateError::Xrc(ExchangeRateError::CryptoBaseAssetNotFound))` for all subsequent calls (mirroring the existing `test_periodic_calls_the_xrc_and_call_fails` test pattern at L530–554).
3. Advance the mock clock by 60+ minutes (simulating sustained XRC outage).
4. Call `tokens_to_cycles(Tokens::from_e8s(100 * E8))` and assert it returns `Ok(cycles)` computed at `xdr_permyriad_per_icp = 50_000` — demonstrating the stale rate is used without rejection.
5. Assert that `cycles > expected_cycles_at_current_market_rate` (using a lower current rate, e.g., `40_000`) to quantify the over-minting.