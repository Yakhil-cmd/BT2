Audit Report

## Title
Missing Freshness Check on `icp_xdr_conversion_rate` in `tokens_to_cycles()` Enables Stale-Rate Arbitrage During XRC Outage - (File: `rs/nns/cmc/src/main.rs`)

## Summary
The CMC function `tokens_to_cycles()` reads `state.icp_xdr_conversion_rate` and uses only the `xdr_permyriad_per_icp` field, performing no check on `timestamp_seconds` against the current time. When the Exchange Rate Canister (XRC) is unavailable, the CMC retries every minute but never invalidates or age-gates the stored rate. Any unprivileged user can exploit this by submitting ICP-to-cycles conversion requests while the stored rate is arbitrarily stale, receiving excess cycles relative to the current market rate.

## Finding Description
`tokens_to_cycles()` at `rs/nns/cmc/src/main.rs:1900–1923` extracts only `xdr_permyriad_per_icp` from the stored rate and performs no timestamp comparison:

```rust
let xdr_permyriad_per_icp = state
    .icp_xdr_conversion_rate
    .as_ref()
    .map(|rate| rate.xdr_permyriad_per_icp);
```

This function is called unconditionally by all three public ICP→cycles paths: `process_create_canister()` (L1932), `process_mint_cycles()` (L1965), and `process_top_up()` (L1991).

The rate refresh mechanism in `exchange_rate_canister.rs` schedules retries at 1-minute intervals on XRC failure (L153–161) but does not clear or invalidate `state.icp_xdr_conversion_rate`. The `do_set_icp_xdr_conversion_rate()` function at `main.rs:1009–1040` enforces only monotonicity (new timestamp must exceed current timestamp) — it imposes no maximum age on the stored rate. There is no point in any of the three notify call paths where `rate.timestamp_seconds` is compared against `ic_cdk::api::time() / 1_000_000_000` before the conversion executes.

The XRC is explicitly anticipated to fail: the CMC's own error handling (`UpdateExchangeRateError::FailedToRetrieveRate`, `FailedToSetRate`, `InvalidRate`) all schedule retries without touching the stored rate. The default initial rate is hardcoded to May 10, 2021 (`DEFAULT_ICP_XDR_CONVERSION_RATE_TIMESTAMP_SECONDS = 1620633600`), confirming the system can operate with an arbitrarily old rate.

## Impact Explanation
During any XRC outage, an attacker who observes that the stored rate is higher than the current market rate can purchase ICP cheaply on the open market and convert it to cycles at the inflated stale rate via `notify_mint_cycles`, `notify_top_up`, or `notify_create_canister`. Each such conversion mints more cycles per ICP than the protocol should issue, constituting **illegal minting** of cycles. The CMC's per-period cycle minting limiter (`DEFAULT_CYCLES_LIMIT = 150e15` cycles/month) bounds but does not eliminate the damage — at a 2.5× rate discrepancy, an attacker can extract tens of thousands of ICP worth of excess cycles before the limit is reached. This matches the allowed High impact: "Significant XRC, NNS, or infrastructure security impact with concrete user or protocol harm" and potentially Critical: "Illegal minting… involving exorbitant ICP/Cycles."

## Likelihood Explanation
The XRC is a live canister on the NNS subnet subject to upgrades and transient failures. The CMC's own code explicitly handles XRC unavailability with retry logic, confirming this is a known operational scenario. The attack requires only: (1) an XRC outage of any duration, (2) ICP market price movement during that window, and (3) a standard permissionless ICP transfer to the CMC's subaccount. No special privileges, leaked keys, or social engineering are required. The attacker can monitor the CMC's certified state to observe the stored rate's timestamp and compare it against market prices in real time.

## Recommendation
In `tokens_to_cycles()`, retrieve the current time via `ic_cdk::api::time() / 1_000_000_000` and compare it against `rate.timestamp_seconds`. If the difference exceeds a defined maximum staleness threshold (e.g., `REFRESH_RATE_INTERVAL_SECONDS * N` for some small N, or a hard cap such as 30 minutes), return a `NotifyError::Other` with a descriptive message indicating the rate is stale, allowing callers to retry once the XRC recovers. The threshold should be chosen to tolerate normal XRC latency while bounding the staleness window exploitable by arbitrageurs.

## Proof of Concept
1. Deploy a local replica with the CMC and a mock XRC that returns a fixed rate R (e.g., 50,000 XDR permyriad per ICP = 5 XDR/ICP).
2. Allow the CMC to store rate R at time T.
3. Disable the mock XRC (return errors on all calls). Confirm via CMC state that `icp_xdr_conversion_rate.timestamp_seconds` remains T while wall-clock time advances.
4. After time T + 30 minutes (simulated via `ic_cdk::api::time` mock), call `notify_mint_cycles` with an ICP transfer.
5. Observe that `tokens_to_cycles()` uses rate R without error — no staleness check fires.
6. Compute cycles received vs. cycles that would be minted at a corrected lower rate; confirm the excess.
7. A deterministic PocketIC integration test can implement this by: setting XRC to fail, advancing time by >5 minutes, submitting a notify call, and asserting that cycles minted equal `amount * R` rather than rejecting with a staleness error. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) [6](#0-5) [7](#0-6)

### Citations

**File:** rs/nns/cmc/src/main.rs (L1022-1030)
```rust
    mutate_state(safe_state, |state| {
        if let Some(current_conversion_rate) = state.icp_xdr_conversion_rate.as_ref()
            && proposed_conversion_rate.timestamp_seconds
                <= current_conversion_rate.timestamp_seconds
        {
            return Err(
                "Proposed conversion rate must have greater timestamp than current one".to_string(),
            );
        }
```

**File:** rs/nns/cmc/src/main.rs (L1900-1923)
```rust
fn tokens_to_cycles(amount: Tokens) -> Result<Cycles, NotifyError> {
    with_state(|state| {
        let xdr_permyriad_per_icp = state
            .icp_xdr_conversion_rate
            .as_ref()
            .map(|rate| rate.xdr_permyriad_per_icp);
        match xdr_permyriad_per_icp {
            Some(xdr_permyriad_per_icp) => Ok(TokensToCycles {
                xdr_permyriad_per_icp,
                cycles_per_xdr: state.cycles_per_xdr,
            }
            .to_cycles(amount)),
            None => {
                let error_message =
                    "No conversion rate found in CMC, notification aborted".to_string();
                print(&error_message);
                Err(NotifyError::Other {
                    error_code: NotifyErrorCode::Internal as u64,
                    error_message,
                })
            }
        }
    })
}
```

**File:** rs/nns/cmc/src/main.rs (L1931-1932)
```rust
) -> Result<CanisterId, NotifyError> {
    let cycles = tokens_to_cycles(amount)?;
```

**File:** rs/nns/cmc/src/main.rs (L1964-1965)
```rust
) -> NotifyMintCyclesResult {
    let cycles = tokens_to_cycles(amount)?;
```

**File:** rs/nns/cmc/src/main.rs (L1990-1991)
```rust
) -> Result<Cycles, NotifyError> {
    let cycles = tokens_to_cycles(amount)?;
```

**File:** rs/nns/cmc/src/exchange_rate_canister.rs (L15-16)
```rust
/// If the rate is older than this value, the CMC should ask for a new rate.
const REFRESH_RATE_INTERVAL_SECONDS: u64 = 5 * ONE_MINUTE_SECONDS;
```

**File:** rs/nns/cmc/src/exchange_rate_canister.rs (L149-163)
```rust
                Err(error) => match error {
                    UpdateExchangeRateError::UpdateAlreadyInProgress => {}
                    UpdateExchangeRateError::Disabled => {}
                    UpdateExchangeRateError::NotReadyToGetRate(_) => {}
                    UpdateExchangeRateError::FailedToRetrieveRate(_)
                    | UpdateExchangeRateError::FailedToSetRate(_)
                    | UpdateExchangeRateError::InvalidRate(_) => {
                        state.update_exchange_rate_canister_state.replace(
                            UpdateExchangeRateState::get_rate_at_next_minute(
                                self.current_minute_in_seconds,
                            ),
                        );
                    }
                },
            }
```
