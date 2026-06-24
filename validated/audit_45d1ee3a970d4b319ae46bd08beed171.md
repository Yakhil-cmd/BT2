Audit Report

## Title
No Staleness Check on ICP/XDR Rate Before Minting Cycles - (File: rs/nns/cmc/src/main.rs)

## Summary

The `tokens_to_cycles` function in the Cycles Minting Canister reads the stored `icp_xdr_conversion_rate` and uses it for conversion with no check on the age of the rate. If the Exchange Rate Canister (XRC) is unavailable for an extended period, the CMC silently continues minting cycles at the last known rate. Any unprivileged user can call `notify_top_up` or `notify_mint_cycles` during such a gap to receive more cycles per ICP than the current market rate warrants, constituting irreversible over-minting at the protocol's expense.

## Finding Description

`tokens_to_cycles` at `rs/nns/cmc/src/main.rs` L1900–1923 extracts only `rate.xdr_permyriad_per_icp` from the stored rate and performs no check on `rate.timestamp_seconds`:

```rust
fn tokens_to_cycles(amount: Tokens) -> Result<Cycles, NotifyError> {
    with_state(|state| {
        let xdr_permyriad_per_icp = state
            .icp_xdr_conversion_rate
            .as_ref()
            .map(|rate| rate.xdr_permyriad_per_icp);  // timestamp ignored
        match xdr_permyriad_per_icp {
            Some(xdr_permyriad_per_icp) => Ok(TokensToCycles { ... }.to_cycles(amount)),
            None => Err(...)
        }
    })
}
``` [1](#0-0) 

All three public minting entry points call this function directly:
- `process_top_up` → `notify_top_up` [2](#0-1) 
- `process_create_canister` → `notify_create_canister` [3](#0-2) 
- `process_mint_cycles` → `notify_mint_cycles` (same pattern)

The rate is refreshed every `REFRESH_RATE_INTERVAL_SECONDS` (5 minutes) via heartbeat. [4](#0-3) 

On XRC failure, the next attempt is scheduled one minute later, but the stale rate remains in state and is used without restriction: [5](#0-4) 

`do_set_icp_xdr_conversion_rate` only rejects a new rate if its timestamp is not strictly greater than the stored one — it enforces monotonicity, not maximum age: [6](#0-5) 

`validate_exchange_rate` only checks the number of data sources, not the age of the rate: [7](#0-6) 

By contrast, governance's `should_refresh_xdr_rate` already demonstrates the correct pattern — comparing `rate.timestamp_seconds` against `now_seconds` and flagging rates older than `ONE_DAY_SECONDS` — but this check is absent from the CMC minting path: [8](#0-7) 

## Impact Explanation

If the XRC is unavailable for hours and ICP price drops materially (10–20% moves in hours are historically plausible), any unprivileged user can call `notify_top_up` or `notify_mint_cycles` to receive cycles computed at the stale (higher) rate. The ICP is burned and the excess cycles are irreversibly minted — a permanent discrepancy in the cycles economy. This matches the allowed impact: **illegal minting of cycles / protocol insolvency** at the High–Critical boundary. The XRC is explicitly listed as an in-scope target. Severity is **High** because triggering a multi-hour XRC outage is not trivially achievable by an attacker alone, but the over-minting is unbounded in aggregate across all users during the gap.

## Likelihood Explanation

XRC failure modes (`StablecoinRateTooFewRates`, `CryptoBaseAssetNotFound`, canister upgrade, subnet issues) are already exercised in integration tests, confirming the error-retry path is real and reachable. No special privileges are required to call `notify_top_up`. The attacker only needs to observe that the CMC rate has not updated (queryable via `get_icp_xdr_conversion_rate`) and that the current market price is lower than the stored rate, then submit ICP for conversion.

## Recommendation

In `tokens_to_cycles`, compare `rate.timestamp_seconds` against `now_seconds()` and reject if the rate exceeds a configurable maximum age (e.g., 30–60 minutes):

```rust
let age_seconds = now_seconds().saturating_sub(rate.timestamp_seconds);
if age_seconds > MAX_RATE_AGE_SECONDS {
    return Err(NotifyError::Other {
        error_code: NotifyErrorCode::Internal as u64,
        error_message: format!("ICP/XDR rate is stale ({age_seconds}s old)"),
    });
}
```

`now_seconds` is already imported in `rs/nns/cmc/src/main.rs`. [9](#0-8)  The threshold should be a named constant and configurable via upgrade argument.

## Proof of Concept

1. Deploy CMC and XRC in a PocketIC/state-machine test. Establish a valid rate at time T (`xdr_permyriad_per_icp = 50_000`).
2. Reinstall the mock XRC to return `ExchangeRateError::StablecoinRateTooFewRates` (as already done in the existing integration test at `rs/nns/integration_tests/src/cycles_minting_canister_with_exchange_rate_canister.rs` L162–185).
3. Advance time by 2+ hours; tick heartbeat repeatedly. Confirm via `get_icp_xdr_conversion_rate` that the stored rate timestamp has not advanced.
4. Separately reduce the mock market rate to `xdr_permyriad_per_icp = 40_000` (20% drop).
5. Call `notify_top_up` with 1 ICP from an unprivileged principal.
6. Assert that the cycles deposited equal those computed from the stale rate (50,000 permyriad) rather than the current rate (40,000 permyriad) — confirming a 25% over-mint with no error returned.

### Citations

**File:** rs/nns/cmc/src/main.rs (L25-25)
```rust
use ic_nervous_system_time_helpers::now_seconds;
```

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

**File:** rs/nns/cmc/src/main.rs (L1925-1932)
```rust
async fn process_create_canister(
    controller: PrincipalId,
    from: AccountIdentifier,
    amount: Tokens,
    subnet_selection: Option<SubnetSelection>,
    settings: Option<CanisterSettings>,
) -> Result<CanisterId, NotifyError> {
    let cycles = tokens_to_cycles(amount)?;
```

**File:** rs/nns/cmc/src/main.rs (L1985-1991)
```rust
async fn process_top_up(
    canister_id: CanisterId,
    from: AccountIdentifier,
    amount: Tokens,
    limiter_to_use: CyclesMintingLimiterSelector,
) -> Result<Cycles, NotifyError> {
    let cycles = tokens_to_cycles(amount)?;
```

**File:** rs/nns/cmc/src/exchange_rate_canister.rs (L15-16)
```rust
/// If the rate is older than this value, the CMC should ask for a new rate.
const REFRESH_RATE_INTERVAL_SECONDS: u64 = 5 * ONE_MINUTE_SECONDS;
```

**File:** rs/nns/cmc/src/exchange_rate_canister.rs (L149-165)
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
        });
    }
```

**File:** rs/nervous_system/clients/src/exchange_rate_canister_client.rs (L111-129)
```rust
pub fn validate_exchange_rate(
    exchange_rate: &ExchangeRate,
) -> Result<(), ValidateExchangeRateError> {
    if exchange_rate.metadata.base_asset_num_received_rates < MINIMUM_ICP_SOURCES {
        return Err(ValidateExchangeRateError::NotEnoughIcpSources {
            received: exchange_rate.metadata.base_asset_num_received_rates,
            queried: exchange_rate.metadata.base_asset_num_queried_sources,
        });
    }

    if exchange_rate.metadata.quote_asset_num_received_rates < MINIMUM_CXDR_SOURCES {
        return Err(ValidateExchangeRateError::NotEnoughCxdrSources {
            received: exchange_rate.metadata.quote_asset_num_received_rates,
            queried: exchange_rate.metadata.quote_asset_num_queried_sources,
        });
    }

    Ok(())
}
```

**File:** rs/nns/governance/src/governance.rs (L6336-6348)
```rust
    fn should_refresh_xdr_rate(&self) -> bool {
        let xdr_conversion_rate = &self.heap_data.xdr_conversion_rate;

        let now_seconds = self.env.now();

        let seconds_since_last_conversion_rate_refresh =
            now_seconds.saturating_sub(xdr_conversion_rate.timestamp_seconds);

        // Return `true` if more than 1 day has passed since the last `xdr_conversion_rate` was
        // updated. This assumes that `xdr_conversion_rate.timestamp_seconds` is rounded down to
        // the nearest day's beginning.
        seconds_since_last_conversion_rate_refresh > ONE_DAY_SECONDS
    }
```
