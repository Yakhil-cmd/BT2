Let me verify the key code references in this claim.

All code references check out. Let me confirm the `build_unsigned_transaction_from_inputs` path and the `DustOutput` branch behavior for completeness.

The claim is valid. All cited code paths are confirmed:

1. `retrieve_btc` reads `fee_based_retrieve_btc_min_amount` at call time and burns ckBTC before queuing. [1](#0-0) [2](#0-1) 

2. `submit_pending_requests` fetches a fresh fee rate, atomically updates `fee_based_retrieve_btc_min_amount`, and passes the new rate to `build_unsigned_transaction`. [3](#0-2) [4](#0-3) 

3. `BuildTxError::AmountTooLow` is returned when `fee + minter_fee > amount`. [5](#0-4) 

4. The `AmountTooLow` branch calls only `remove_retrieve_btc_request` — no `reimburse_canceled_requests`. [6](#0-5) 

5. `remove_retrieve_btc_request` only records an event and pushes to finalized — no reimbursement. [7](#0-6) 

6. `WithdrawalReimbursementReason` has only an `InvalidTransaction` variant — no `AmountTooLow` variant exists. [8](#0-7) 

7. The fixed `PER_REQUEST_RBF_BOUND = 22_100` provides only ~100 sat/vbyte of headroom for a 221-vbyte transaction. [9](#0-8) 

8. The codebase itself documents a real June 2025 incident where the fee estimate was off by ~14×. [10](#0-9) 

---

Audit Report

## Title
Fee spike between `retrieve_btc` acceptance and batch processing causes permanent ckBTC burn with no BTC delivery and no reimbursement — (`rs/bitcoin/ckbtc/minter/src/lib.rs`, `rs/bitcoin/ckbtc/minter/src/fees/mod.rs`)

## Summary
The `fee_based_retrieve_btc_min_amount` guard in `retrieve_btc` is evaluated at call time using the last cached fee rate, and ckBTC is burned immediately. When `submit_pending_requests` fires, it fetches a fresh fee rate from the Bitcoin canister and uses it for `build_unsigned_transaction`. If the fee rate has spiked beyond the fixed RBF buffer (~100 sat/vbyte headroom for a 221-vbyte transaction), `BuildTxError::AmountTooLow` is returned. Unlike `InvalidTransaction`, the `AmountTooLow` branch finalizes the request without scheduling any reimbursement, permanently destroying the user's ckBTC with no BTC delivered and no ckBTC returned.

## Finding Description
**Root cause:** The minimum withdrawal amount check and the actual fee check use different fee rates — the former uses a cached rate at `retrieve_btc` call time, the latter uses a freshly fetched rate at batch processing time. The `AmountTooLow` error path lacks a reimbursement step.

**Code path:**
1. `retrieve_btc` reads `s.fee_based_retrieve_btc_min_amount` (cached, stale) and accepts the request if `args.amount >= min_retrieve_amount`. ckBTC is then burned via `burn_ckbtcs`. (`rs/bitcoin/ckbtc/minter/src/updates/retrieve_btc.rs`, L166–171, L209–210)
2. `submit_pending_requests` calls `estimate_fee_per_vbyte`, which fetches a fresh fee from the Bitcoin canister and atomically updates `s.fee_based_retrieve_btc_min_amount` to the new higher value. (`rs/bitcoin/ckbtc/minter/src/lib.rs`, L245–249, L358–361)
3. The fresh fee rate is passed to `build_unsigned_transaction`. Inside `build_unsigned_transaction_from_inputs`, `fee_estimator.evaluate_transaction_fee(&unsigned_tx, fee_rate)` computes the actual fee at the new rate. If `fee + minter_fee > amount`, `BuildTxError::AmountTooLow` is returned. (`rs/bitcoin/ckbtc/minter/src/lib.rs`, L1304–1308)
4. The `AmountTooLow` match arm calls `state::audit::remove_retrieve_btc_request(s, request, FinalizedStatus::AmountTooLow, runtime)` for each request in the batch. (`rs/bitcoin/ckbtc/minter/src/lib.rs`, L412–434)
5. `remove_retrieve_btc_request` only records a `RemovedRetrieveBtcRequest` event and pushes to `finalized_requests`. No reimbursement task is scheduled. (`rs/bitcoin/ckbtc/minter/src/state/audit.rs`, L67–84)
6. `WithdrawalReimbursementReason` has only an `InvalidTransaction` variant; there is no `AmountTooLow` variant, making the reimbursement path structurally absent. (`rs/bitcoin/ckbtc/minter/src/reimbursement/mod.rs`, L39–43)

**Why existing guards fail:** The `fee_based_minimum_withdrawal_amount` formula adds a fixed `PER_REQUEST_RBF_BOUND = 22_100` sats as a buffer. For a 221-vbyte transaction, this covers only ~100 sat/vbyte of fee increase. Bitcoin fees routinely spike by multiples of this. The minter's own codebase documents a June 2025 incident where the fee estimate was 142 millisat/vbyte when the actual median was 2,000 millisat/vbyte (~14× discrepancy). (`rs/bitcoin/ckbtc/minter/src/fees/mod.rs`, L77–87, L130–147)

## Impact Explanation
Any ckBTC holder who submits a `retrieve_btc` request near the minimum withdrawal amount during a low-fee period permanently loses their ckBTC if fees spike before the batch is processed. The ckBTC ledger records a burn; the minter records `FinalizedStatus::AmountTooLow`; no BTC is sent; no ckBTC is minted back. This is a concrete, permanent loss of in-scope chain-key assets (ckBTC) with no recovery path. This matches the **High** impact class: "Significant Chain Fusion, ck-token, ledger... security impact with concrete user or protocol harm."

## Likelihood Explanation
Any unprivileged ckBTC holder can trigger this without any special access. The required condition — a Bitcoin fee spike exceeding ~100 sat/vbyte from a low base between `retrieve_btc` call time and batch processing time — is historically common (Ordinals, BRC-20 events, halving periods). The minter's own code documents a real incident (June 2025) with a 14× fee estimation error. The window between acceptance and batch processing can span minutes to hours (`max_time_in_queue_nanos`). This is not a theoretical edge case; it is a documented failure mode.

## Recommendation
1. **Reimburse on `AmountTooLow`**: Treat `BuildTxError::AmountTooLow` the same as `InvalidTransaction` — add an `AmountTooLow` variant to `WithdrawalReimbursementReason` and call `reimburse_canceled_requests` so the user's ckBTC is returned (minus a small processing fee).
2. **Re-validate at batch time**: Before finalizing a request as `AmountTooLow`, verify whether the request amount was above the minimum at acceptance time; if so, reimburse in full.
3. **Scale the RBF buffer**: Replace the fixed `PER_REQUEST_RBF_BOUND = 22_100` with a fee-rate-proportional multiplier so the minimum scales with fee volatility rather than providing a fixed absolute headroom.

## Proof of Concept
State-machine test (deterministic, no mainnet interaction required):
1. Initialize minter with fee percentiles at 1 sat/vbyte → `fee_based_retrieve_btc_min_amount` = `retrieve_btc_min_amount` (e.g., 100,000 sats).
2. Call `retrieve_btc(amount=100_000)` → accepted, ckBTC burned, request queued.
3. Update fee percentiles to 500 sat/vbyte in the mock Bitcoin canister.
4. Tick the timer → `submit_pending_requests` → `estimate_fee_per_vbyte` fetches 500 sat/vbyte, updates state → `build_unsigned_transaction` with 500 sat/vbyte → actual fee = 500 × 221 = 110,500 sats → `110,500 + minter_fee > 100,000` → `BuildTxError::AmountTooLow`.
5. Assert: `retrieve_btc_status(block_index) == FinalizedStatus::AmountTooLow`, no reimbursement mint recorded on the ledger, ckBTC supply decreased by 100,000 sats with no corresponding BTC transaction.

### Citations

**File:** rs/bitcoin/ckbtc/minter/src/updates/retrieve_btc.rs (L166-171)
```rust
    let (min_retrieve_amount, btc_network) =
        read_state(|s| (s.fee_based_retrieve_btc_min_amount, s.btc_network));

    if args.amount < min_retrieve_amount {
        return Err(RetrieveBtcError::AmountTooLow(min_retrieve_amount));
    }
```

**File:** rs/bitcoin/ckbtc/minter/src/updates/retrieve_btc.rs (L209-210)
```rust
    let block_index =
        burn_ckbtcs(caller, args.amount, crate::memo::encode(&burn_memo).into()).await?;
```

**File:** rs/bitcoin/ckbtc/minter/src/lib.rs (L245-249)
```rust
                    mutate_state(|s| {
                        s.last_fee_per_vbyte = fees;
                        s.last_median_fee_per_vbyte = Some(median_fee);
                        s.fee_based_retrieve_btc_min_amount = fee_based_retrieve_btc_min_amount;
                    });
```

**File:** rs/bitcoin/ckbtc/minter/src/lib.rs (L358-384)
```rust
    let fee_millisatoshi_per_vbyte = match estimate_fee_per_vbyte(runtime).await {
        Some(fee) => fee,
        None => return,
    };
    let fee_estimator = read_state(|s| runtime.fee_estimator(s));
    let max_num_inputs_in_transaction = read_state(|s| s.max_num_inputs_in_transaction);

    let maybe_sign_request = state::mutate_state(|s| {
        let batch = s.build_batch(MAX_REQUESTS_PER_BATCH);

        if batch.is_empty() {
            return None;
        }

        let outputs: Vec<_> = batch
            .iter()
            .map(|req| (req.address.clone(), req.amount))
            .collect();

        match build_unsigned_transaction(
            &mut s.available_utxos,
            outputs,
            &main_address,
            max_num_inputs_in_transaction,
            fee_millisatoshi_per_vbyte,
            &fee_estimator,
        ) {
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

**File:** rs/bitcoin/ckbtc/minter/src/lib.rs (L1304-1308)
```rust
    let fee = fee_estimator.evaluate_transaction_fee(&unsigned_tx, fee_rate);

    if fee + minter_fee > amount {
        return Err(BuildTxError::AmountTooLow);
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

**File:** rs/bitcoin/ckbtc/minter/src/reimbursement/mod.rs (L39-43)
```rust
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize, candid::CandidType)]
pub enum WithdrawalReimbursementReason {
    #[serde(rename = "invalid_transaction")]
    InvalidTransaction(InvalidTransactionError),
}
```

**File:** rs/bitcoin/ckbtc/minter/src/fees/mod.rs (L77-87)
```rust
    /// An estimated fee per vbyte of 142 millisatoshis per vbyte was selected around 2025.06.21 01:09:50 UTC
    /// for Bitcoin Mainnet, whereas the median fee around that time should have been 2_000.
    /// Until we know the root cause, we ensure that the estimated fee has a meaningful minimum value.
    const fn minimum_fee_per_vbyte(&self) -> FeeRate {
        let rate = match &self.network {
            Network::Mainnet => 1_500,
            Network::Testnet => 1_000,
            Network::Regtest => 0,
        };
        FeeRate::from_millis_per_byte(rate)
    }
```

**File:** rs/bitcoin/ckbtc/minter/src/fees/mod.rs (L130-147)
```rust
    fn fee_based_minimum_withdrawal_amount(&self, median_fee_rate: FeeRate) -> Satoshi {
        match self.network {
            Network::Mainnet | Network::Testnet => {
                const PER_REQUEST_RBF_BOUND: u64 = 22_100;
                const PER_REQUEST_VSIZE_BOUND: u64 = 221;
                const PER_REQUEST_MINTER_FEE_BOUND: u64 = 305;

                ((PER_REQUEST_RBF_BOUND
                    + median_fee_rate.fee_ceil(PER_REQUEST_VSIZE_BOUND)
                    + PER_REQUEST_MINTER_FEE_BOUND
                    + self.check_fee)
                    / 50_000) //TODO DEFI-2187: adjust increment of minimum withdrawal amount to be a multiple of retrieve_btc_min_amount/2
                    * 50_000
                    + self.retrieve_btc_min_amount
            }
            Network::Regtest => self.retrieve_btc_min_amount,
        }
    }
```
