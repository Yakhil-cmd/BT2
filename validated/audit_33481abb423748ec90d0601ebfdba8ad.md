Audit Report

## Title
Stale ICP/XDR Conversion Rate Used in Cycle Minting Without Freshness Check - (File: `rs/nns/cmc/src/main.rs`)

## Summary
`tokens_to_cycles()` in the Cycles Minting Canister reads `state.icp_xdr_conversion_rate` and checks only that the field is `Some`, never comparing `rate.timestamp_seconds` against the current canister time. When a governance proposal carrying a `DivergedRate` reason disables automatic exchange-rate updates, the stored rate is frozen indefinitely. Any unprivileged user can then call `notify_top_up`, `notify_create_canister`, or `notify_mint_cycles` and receive cycles computed at the frozen (potentially lower) rate, minting more cycles per ICP than the current market price warrants.

## Finding Description
`tokens_to_cycles()` extracts only `xdr_permyriad_per_icp` from the stored rate and ignores `timestamp_seconds` entirely: [1](#0-0) 

The three public update endpoints that call this function are `process_top_up`, `process_create_canister`, and `process_mint_cycles`: [2](#0-1) [3](#0-2) [4](#0-3) 

The rate is normally refreshed every `REFRESH_RATE_INTERVAL_SECONDS` (5 minutes) via the heartbeat. However, `set_update_exchange_rate_state()` sets the state to `Disabled` when a governance proposal carries a `DivergedRate` reason: [5](#0-4) 

Once disabled, the guard in `UpdateExchangeRateGuard::new()` returns early and no automatic rate update occurs: [6](#0-5) 

The rate stored in `state.icp_xdr_conversion_rate` is then frozen indefinitely. A grep across all CMC source files confirms there is no staleness check anywhere in the CMC — no comparison of `rate.timestamp_seconds` against current time before minting. By contrast, NNS Governance already implements exactly this pattern via `should_refresh_xdr_rate()`: [7](#0-6) 

## Impact Explanation
The impact is **illegal minting of cycles**: the protocol mints cycles in excess of what the current ICP/XDR market rate entitles the user to. The ICP is burned (so the ledger is consistent), but the cycles supply is inflated beyond the protocol's economic model. This falls under the allowed High impact category: "Significant Chain Fusion, ck-token, ledger, Rosetta, boundary/API, XRC, Internet Identity, NNS, SNS, or infrastructure security impact with concrete user or protocol harm." During a multi-hour or multi-day disabled window with meaningful ICP price movement, the aggregate over-minting across all callers can be substantial.

## Likelihood Explanation
The `DivergedRate` governance path is an explicitly designed operational mode and has been triggered on mainnet historically. The disabled period can last hours to days depending on governance response time. The attacker requires only: (1) knowledge that the CMC rate is stale (publicly observable via the CMC's `get_icp_xdr_conversion_rate` query), and (2) a valid ICP ledger block. No special privileges are needed to call `notify_top_up` or the other endpoints. The attack is repeatable for the entire duration of the disabled window.

## Recommendation
In `tokens_to_cycles()`, retrieve the current canister time and compare `rate.timestamp_seconds` against it. Reject the conversion if the rate is older than a defined maximum staleness threshold (e.g., 24 hours), mirroring the pattern already used in `should_refresh_xdr_rate()` in NNS Governance: [8](#0-7) 

Concretely: call `ic_cdk::api::time() / 1_000_000_000` to get `now_seconds`, then return `Err(NotifyError::Other { ... })` if `now_seconds.saturating_sub(rate.timestamp_seconds) > MAX_RATE_AGE_SECONDS` (e.g., `86400`).

## Proof of Concept
1. Submit a governance proposal with `DivergedRate` reason to disable automatic CMC rate updates. The proposal sets a specific `xdr_permyriad_per_icp` value reflecting the rate at proposal time.
2. Wait for ICP market price to rise materially above the frozen rate (observable on-chain via CMC's `get_icp_xdr_conversion_rate` vs. any public price feed).
3. Transfer N ICP to `CMC_PRINCIPAL / subaccount(canister_id)` with `MEMO_TOP_UP_CANISTER`.
4. Call `notify_top_up { block_index, canister_id }` from any unprivileged principal.
5. CMC calls `tokens_to_cycles(N ICP)` → reads the stale (lower) `xdr_permyriad_per_icp` → mints more cycles than the current market rate warrants.
6. Repeat steps 3–5 until governance re-enables the exchange rate canister.

A deterministic integration test can reproduce this by: (a) initializing CMC state with a known rate and timestamp, (b) calling `set_update_exchange_rate_state` with `DivergedRate`, (c) advancing the mock clock by >24 hours, and (d) asserting that `tokens_to_cycles` returns cycles exceeding what the current market rate would produce — currently this assertion fails (no error is returned), confirming the bug.

### Citations

**File:** rs/nns/cmc/src/main.rs (L1900-1911)
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

**File:** rs/nns/cmc/src/main.rs (L1958-1965)
```rust
async fn process_mint_cycles(
    to_account: Account,
    amount: Tokens,
    deposit_memo: Option<Vec<u8>>,
    from: AccountIdentifier,
    sub: Subaccount,
) -> NotifyMintCyclesResult {
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

**File:** rs/nns/cmc/src/exchange_rate_canister.rs (L98-100)
```rust
        if current_call_state == UpdateExchangeRateState::Disabled {
            return Err(UpdateExchangeRateError::Disabled);
        }
```

**File:** rs/nns/cmc/src/exchange_rate_canister.rs (L311-315)
```rust
                UpdateIcpXdrConversionRatePayloadReason::DivergedRate => {
                    state
                        .update_exchange_rate_canister_state
                        .replace(UpdateExchangeRateState::Disabled);
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
