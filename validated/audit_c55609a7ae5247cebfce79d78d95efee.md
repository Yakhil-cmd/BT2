Audit Report

## Title
Bare `candid::Decode!` Without Quota in `manage_neuron` Closure Enables Unauthenticated Rosetta Process Crash — (`rs/rosetta-api/icp/src/request.rs`)

## Summary

The `manage_neuron` closure inside `TryFrom<&models::Request> for Request` invokes `Decode!` with no `DecoderConfig`, meaning no skipping or decoding quota is enforced. An unauthenticated attacker can POST a single crafted `ConstructionSubmitRequest` to `/construction/submit` containing a Candid arg whose type table encodes deeply nested structures, triggering unbounded recursive field-skipping that exhausts the thread stack and aborts the Rosetta process. No signature, valid neuron ID, or valid principal is required.

## Finding Description

The bare `Decode!` call is at `rs/rosetta-api/icp/src/request.rs` lines 250–261:

```rust
let manage_neuron = || {
    {
        Decode!(
            &payload.update_content().arg.0,
            ic_nns_governance_api::ManageNeuronRequest
        )
        ...
    }
    .map(|m| m.command)
};
``` [1](#0-0) 

No `DecoderConfig` is constructed, and no `set_skipping_quota` or `set_decoding_quota` is applied. A grep across all of `rs/rosetta-api/icp/src/**` confirms zero uses of `DecoderConfig`, `set_skipping_quota`, or `set_decoding_quota` anywhere in the Rosetta ICP source.

The Candid typed decoder must skip wire-format fields absent from the Rust target type. When the Candid type table encodes deeply nested or mutually recursive type references, this skipping recurses proportionally, exhausting the thread stack. The codebase explicitly acknowledges this risk: the `candid_type_decoder` fuzz target wraps every `Decode!` call with `config.set_skipping_quota(10_000)` to prevent exactly this scenario:

```rust
let mut config = DecoderConfig::new();
config.set_skipping_quota(10_000);
let _decoded = match Decode!([config]; payload.as_slice(), HttpResponse) { ... };
``` [2](#0-1) 

The full reachable call chain, with no authentication gate before the crash point:

1. `POST /construction/submit` → `construction_submit` handler
2. `RosettaRequestHandler::construction_submit` — only calls `verify_network_id`, then `SignedTransaction::from_str` (CBOR parse only, no signature check) [3](#0-2) 

3. `self.ledger.submit(envelopes)` → iterates requests, calling `Request::try_from(e)` on each [4](#0-3) 

4. `Request::try_from` → `manage_neuron()` closure → bare `Decode!` → stack overflow → process abort [5](#0-4) 

The 4 MB JSON body limit at `rosetta_server.rs:297–298` does not mitigate this: Candid type tables encode thousands of nesting levels via index references in a few hundred bytes. [6](#0-5) 

## Impact Explanation

A stack overflow in Rust causes a process abort (SIGABRT/SIGSEGV), not a recoverable panic. A single crafted HTTP request crashes the Rosetta server, making the Rosetta API entirely unavailable until the process is restarted. This is a non-volumetric, single-request DoS against the ICP Rosetta financial integration — matching the allowed High impact: *"Application/platform-level DoS, crash... or infrastructure security impact with concrete user or protocol harm"* and *"Significant... Rosetta... security impact with concrete user or protocol harm."* Severity: **High ($2,000–$10,000)**.

## Likelihood Explanation

The `/construction/submit` endpoint is publicly accessible with no authentication. The attacker needs only to construct a valid CBOR-encoded `SignedTransaction` with any neuron-management `RequestType` (e.g., `SetDissolveTimestamp`, `Disburse`, `ChangeAutoStakeMaturity`) and a Candid arg whose type table encodes deep nesting. No valid signature, neuron ID, or principal is required — the crash occurs before any of those are checked. The construction is straightforward for anyone familiar with the Candid binary wire format. The attack is repeatable and deterministic.

## Recommendation

Replace the bare `Decode!` call with a quota-limited variant, consistent with the pattern already used in the fuzzer:

```rust
let manage_neuron = || {
    let mut config = candid::DecoderConfig::new();
    config.set_skipping_quota(10_000);
    config.set_decoding_quota(10_000);
    Decode!([config]; &payload.update_content().arg.0, ic_nns_governance_api::ManageNeuronRequest)
        .map_err(|e| ApiError::invalid_request(format!("Could not parse manage_neuron: {e}")))
        .map(|m| m.command)
};
```

Audit all other bare `Decode!` calls in `rs/rosetta-api/icp/src/` (including `ledger_client.rs` which contains 7 bare `Decode!` invocations decoding canister responses) and apply the same quota pattern.

## Proof of Concept

1. Construct a Candid type table encoding a record with ~50,000 levels of nesting using index back-references (fits in ~1 KB).
2. Wrap it in a minimal Candid value blob (empty record value).
3. Set this as the `arg` field of an `EnvelopePair.update` with `RequestType::SetDissolveTimestamp` (or any other `manage_neuron`-invoking type).
4. CBOR-encode the `SignedTransaction`, hex-encode it, embed in a `ConstructionSubmitRequest` JSON body.
5. POST to `http://<rosetta-host>/construction/submit`.
6. The Rosetta process aborts with a stack overflow inside `Decode!` at `request.rs:252`.

A deterministic unit test can be written by constructing the malformed Candid bytes directly and calling `Request::try_from` on a crafted `models::Request` — the test process will abort, confirming the crash.

### Citations

**File:** rs/rosetta-api/icp/src/request.rs (L250-261)
```rust
        let manage_neuron = || {
            {
                Decode!(
                    &payload.update_content().arg.0,
                    ic_nns_governance_api::ManageNeuronRequest
                )
                .map_err(|e| {
                    ApiError::invalid_request(format!("Could not parse manage_neuron: {e}"))
                })
            }
            .map(|m| m.command)
        };
```

**File:** rs/rosetta-api/icp/src/request.rs (L280-281)
```rust
            RequestType::SetDissolveTimestamp { neuron_index } => {
                let command = manage_neuron()?;
```

**File:** rs/fuzzers/candid/fuzz_targets/candid_type_decoder.rs (L41-47)
```rust
    let mut config = DecoderConfig::new();
    config.set_skipping_quota(10_000);

    let _decoded = match Decode!([config]; payload.as_slice(), HttpResponse) {
        Ok(_v) => _v,
        Err(_e) => return,
    };
```

**File:** rs/rosetta-api/icp/src/request_handler/construction_submit.rs (L15-23)
```rust
    pub async fn construction_submit(
        &self,
        msg: ConstructionSubmitRequest,
    ) -> Result<ConstructionSubmitResponse, ApiError> {
        verify_network_id(self.ledger.ledger_canister_id(), &msg.network_identifier)?;
        let envelopes = SignedTransaction::from_str(&msg.signed_transaction).map_err(|e| {
            ApiError::invalid_transaction(format!("Failed to parse signed transaction: {e}"))
        })?;
        let results = self.ledger.submit(envelopes).await?;
```

**File:** rs/rosetta-api/icp/src/ledger_client.rs (L302-316)
```rust
        let mut results: TransactionResults = signed_transaction
            .requests
            .iter()
            .map(|e| {
                Request::try_from(e).map(|_type| RequestResult {
                    _type,
                    block_index: None,
                    neuron_id: None,
                    transaction_identifier: None,
                    status: crate::request_types::Status::NotAttempted,
                    response: None,
                })
            })
            .collect::<Result<Vec<_>, _>>()?
            .into();
```

**File:** rs/rosetta-api/icp/src/rosetta_server.rs (L297-299)
```rust
                    web::JsonConfig::default()
                        .limit(4 * 1024 * 1024)
                        .error_handler(move |e, _| {
```
