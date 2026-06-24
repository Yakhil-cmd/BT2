Audit Report

## Title
Case-Insensitive Bech32 Parsing Bypasses Minter Self-Address Guard in `retrieve_btc` — (File: rs/bitcoin/ckbtc/minter/src/updates/retrieve_btc.rs)

## Summary

The ckBTC minter's `retrieve_btc` and `retrieve_btc_with_approval` endpoints guard against withdrawals to the minter's own address using a case-sensitive string comparison against a lowercase-only canonical address string. Because `BitcoinAddress::parse` explicitly accepts uppercase bech32 input, a caller supplying the minter's address in uppercase bypasses the guard, has their ckBTC burned, and has BTC sent to the minter's own UTXO pool with no reimbursement path triggered. The caller's funds are permanently lost.

## Finding Description

**Guard — case-sensitive string comparison:**

In `retrieve_btc`, the self-address guard compares the raw input string against the minter's canonical address string:

```rust
if args.address == main_address_str {
    ic_cdk::trap("illegal retrieve_btc target");
}
``` [1](#0-0) 

`main_address_str` is produced by `derive_minter_address_str`, which calls `display()` → `encode_bech32()`, always yielding a **lowercase** bech32 string (e.g., `bc1q…`): [2](#0-1) 

The identical guard is present in `retrieve_btc_with_approval`: [3](#0-2) 

**Parser — case-insensitive bech32 acceptance:**

`BitcoinAddress::parse` dispatches on the first character and explicitly handles both `'b'`/`'B'` and `'t'`/`'T'`: [4](#0-3) 

Inside `parse_bip173_address`, the HRP comparison is case-folded: [5](#0-4) 

The existing test suite explicitly confirms that `"BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4"` (uppercase) parses to the same `BitcoinAddress::P2wpkhV0` value as its lowercase equivalent: [6](#0-5) 

**Exploit flow:**

1. Guard check: `"BC1QMINTER…" != "bc1qminter…"` → guard does **not** trap.
2. `BitcoinAddress::parse("BC1QMINTER…", network)` succeeds, returning the same `BitcoinAddress::P2wpkhV0([…])` as the minter's address.
3. In `retrieve_btc`, the BTC checker is called with the raw uppercase string `args.address.clone()`. The minter's address is not on the OFAC blocklist → `Passed`. [7](#0-6) 
4. ckBTC is burned from the caller's account and a `RetrieveBtcRequest` is queued with `address: parsed_address` (the minter's own address): [8](#0-7) 
5. `submit_pending_requests` builds and submits a valid Bitcoin transaction sending BTC to the minter's own address. The transaction confirms on-chain. [9](#0-8) 
6. The confirmed UTXO is absorbed into the minter's `available_utxos` pool. No ckBTC is minted (minting only occurs for UTXOs at per-user deposit addresses, not the minter's main address).

**Why reimbursement does not trigger:**

The withdrawal reimbursement mechanism only fires on `BuildTxError::InvalidTransaction` (e.g., `TooManyInputs`) or `BuildTxError::AmountTooLow`. A transaction to the minter's own address is a valid Bitcoin transaction that builds and confirms successfully — no reimbursement reason is ever scheduled. [10](#0-9) 

## Impact Explanation

This is a **High** severity finding. An unprivileged caller can permanently lose their own ckBTC/BTC by supplying the minter's address in uppercase. The guard that exists specifically to prevent this scenario is bypassed. The BTC is absorbed into the minter's UTXO pool and the ckBTC burn is irreversible — there is no reimbursement path for a successfully confirmed transaction. This constitutes concrete, permanent user fund loss in the ckBTC system, matching the allowed impact: *"Significant Chain Fusion, ck-token, ledger... security impact with concrete user or protocol harm."*

## Likelihood Explanation

The minter's address is publicly queryable. Any caller who submits the minter's address in uppercase (e.g., copied from a UI that renders bech32 in uppercase for readability, or from a QR code scanner that uppercases output) will silently bypass the guard. No special privileges, key material, or consensus manipulation are required — only a standard ingress call to `retrieve_btc` or `retrieve_btc_with_approval`. The attack is repeatable by any principal with a ckBTC balance.

## Recommendation

Replace the string-equality guard with a semantic comparison on the already-parsed `BitcoinAddress` value. Parse the minter's address once and compare structs, not strings:

```rust
// After parsing args.address:
let minter_address = runtime.derive_minter_address(state);
if parsed_address == minter_address {
    ic_cdk::trap("illegal retrieve_btc target");
}
```

This eliminates the case-sensitivity gap entirely. The `BitcoinAddress` enum derives `PartialEq`, so the comparison is exact and encoding-independent. [11](#0-10) 

## Proof of Concept

1. Query the minter's canonical address via `minter_address()`, e.g. `bc1qminter…`.
2. Convert to uppercase: `BC1QMINTER…`.
3. Call `retrieve_btc(RetrieveBtcArgs { address: "BC1QMINTER…", amount: X })` as any unprivileged principal with sufficient ckBTC balance.
4. Observe: guard at L158 does not trap (`"BC1QMINTER…" != "bc1qminter…"`).
5. Observe: `BitcoinAddress::parse("BC1QMINTER…", network)` returns `Ok(BitcoinAddress::P2wpkhV0([…]))` — identical to the minter's address.
6. Observe: BTC checker returns `Passed` (minter's address is not on OFAC blocklist).
7. Observe: ckBTC is burned from caller's account; `RetrieveBtcRequest` is queued with `address = parsed_address`.
8. Observe: minter's processing loop sends BTC to its own address; transaction confirms; UTXO is absorbed into `available_utxos`; no ckBTC is minted; no reimbursement is scheduled.

A deterministic integration test using `CkBtcSetup` (the existing PocketIC harness in `rs/bitcoin/ckbtc/minter/tests/tests.rs`) can reproduce this by: depositing ckBTC to a test user, calling `retrieve_btc` with the minter's address uppercased, advancing time past `MAX_TIME_IN_QUEUE`, and asserting that the user's ckBTC balance decreased, no reimbursement event was emitted, and the minter's `available_utxos` grew.

### Citations

**File:** rs/bitcoin/ckbtc/minter/src/updates/retrieve_btc.rs (L158-160)
```rust
    if args.address == main_address_str {
        ic_cdk::trap("illegal retrieve_btc target");
    }
```

**File:** rs/bitcoin/ckbtc/minter/src/updates/retrieve_btc.rs (L186-202)
```rust
    let btc_checker_principal = read_state(|s| s.btc_checker_principal).map(|id| id.get().into());
    let status = check_address(btc_checker_principal, args.address.clone(), runtime).await?;
    match status {
        BtcAddressCheckStatus::Tainted => {
            log!(
                Priority::Debug,
                "rejected an attempt to withdraw {} BTC to address {} due to failed Bitcoin check",
                crate::tx::DisplayAmount(args.amount),
                args.address,
            );
            return Err(RetrieveBtcError::GenericError {
                error_message: "Destination address is tainted".to_string(),
                error_code: ErrorCode::TaintedAddress as u64,
            });
        }
        BtcAddressCheckStatus::Clean => {}
    }
```

**File:** rs/bitcoin/ckbtc/minter/src/updates/retrieve_btc.rs (L209-214)
```rust
    let block_index =
        burn_ckbtcs(caller, args.amount, crate::memo::encode(&burn_memo).into()).await?;

    let request = RetrieveBtcRequest {
        amount: args.amount,
        address: parsed_address,
```

**File:** rs/bitcoin/ckbtc/minter/src/updates/retrieve_btc.rs (L256-258)
```rust
    if args.address == main_address_str {
        ic_cdk::trap("illegal retrieve_btc target");
    }
```

**File:** rs/bitcoin/ckbtc/minter/src/lib.rs (L372-376)
```rust
        let outputs: Vec<_> = batch
            .iter()
            .map(|req| (req.address.clone(), req.amount))
            .collect();

```

**File:** rs/bitcoin/ckbtc/minter/src/lib.rs (L400-434)
```rust
            Err(BuildTxError::InvalidTransaction(err)) => {
                log!(
                    Priority::Info,
                    "[submit_pending_requests]: error in building transaction ({:?})",
                    err
                );
                let reason = reimbursement::WithdrawalReimbursementReason::InvalidTransaction(err);
                let reimbursement_fee = fee_estimator
                    .reimbursement_fee_for_pending_withdrawal_requests(batch.len() as u64);
                reimburse_canceled_requests(s, batch, reason, reimbursement_fee, runtime);
                None
            }
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

**File:** rs/bitcoin/ckbtc/minter/src/lib.rs (L1809-1811)
```rust
    fn derive_minter_address_str(&self, state: &CkBtcMinterState) -> String {
        self.derive_minter_address(state).display(state.btc_network)
    }
```

**File:** rs/bitcoin/ckbtc/minter/src/address.rs (L17-19)
```rust
#[derive(
    Clone, Eq, PartialEq, Ord, PartialOrd, Debug, Deserialize, Serialize, candid::CandidType,
)]
```

**File:** rs/bitcoin/ckbtc/minter/src/address.rs (L80-83)
```rust
            Some('b') => parse_bip173_address(address, network),
            Some('B') => parse_bip173_address(address, network),
            Some('t') => parse_bip173_address(address, network),
            Some('T') => parse_bip173_address(address, network),
```

**File:** rs/bitcoin/ckbtc/minter/src/address.rs (L344-344)
```rust
    if found_hrp.to_lowercase() != expected_hrp {
```

**File:** rs/bitcoin/ckbtc/minter/src/address.rs (L471-480)
```rust
        assert_eq!(
            Ok(BitcoinAddress::P2wpkhV0([
                117, 30, 118, 232, 25, 145, 150, 212, 84, 148, 28, 69, 209, 179, 163, 35, 241, 67,
                59, 214
            ])),
            BitcoinAddress::parse(
                "BC1QW508D6QEJXTDG4Y5R3ZARVARY0C5XW7KV8F3T4",
                Network::Mainnet
            )
        );
```
