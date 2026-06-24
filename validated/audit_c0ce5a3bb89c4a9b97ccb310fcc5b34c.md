Audit Report

## Title
Unchecked `updates[0]` Index on Empty `Vec<EnvelopePair>` Causes Panic in `construction_parse` — (`rs/rosetta-api/icp/src/request_handler/construction_parse.rs`)

## Summary
The `construction_parse` handler unconditionally indexes `updates[0]` on the inner `Vec<EnvelopePair>` of each `(RequestType, Vec<EnvelopePair>)` tuple in a `SignedTransaction`, with no guard against an empty vector. An unauthenticated attacker can POST a CBOR-encoded `SignedTransaction` containing a tuple with an empty `Vec<EnvelopePair>`, triggering an out-of-bounds Rust panic. The endpoint is publicly accessible with no authentication, making this a reliable per-request availability disruption of the ICP Rosetta API server.

## Finding Description
`SignedTransaction` is defined as `Vec<(RequestType, Vec<EnvelopePair>)>` with no minimum-length constraint on the inner vector. [1](#0-0) 

`TryFrom<ConstructionParseRequest> for ParsedTransaction` performs only CBOR deserialization — it does not validate that any inner `Vec<EnvelopePair>` is non-empty. [2](#0-1) 

After deserialization, `construction_parse` iterates over `signed_transaction.requests` and unconditionally accesses `updates[0]`: [3](#0-2) 

A `SignedTransaction` with `requests: vec![(RequestType::Send, vec![])]` is structurally valid CBOR and passes `serde_cbor::from_slice` without error. When the iterator reaches the tuple with the empty `Vec<EnvelopePair>`, `updates[0]` panics with an out-of-bounds index. There are no intermediate guards between deserialization and this access.

The endpoint is registered on the public actix-web HTTP server with no authentication: [4](#0-3) 

The synchronous `req_handler.construction_parse()` call is invoked directly inside the async handler without `spawn_blocking`. A panic unwinds through the tokio task, dropping the connection without sending a proper HTTP error response to the client.

## Impact Explanation
This matches the **High ($2,000–$10,000)** impact class: *"Application/platform-level DoS, crash, certified-state disruption, or subnet availability impact not based on raw volumetric DDoS"* and *"Significant Rosetta … security impact with concrete user or protocol harm."* The Rosetta API is explicitly in-scope as a financial integration. An attacker can repeatedly trigger the panic to degrade server availability: each crafted request causes a connection reset instead of a proper HTTP error, and sustained attacks exhaust worker capacity or disrupt legitimate clients relying on the Rosetta API for ICP transaction construction and submission.

## Likelihood Explanation
No authentication or special privileges are required. The `/construction/parse` endpoint is publicly accessible. Crafting the payload requires only basic CBOR serialization (any standard CBOR library). The `SignedTransaction` type has no minimum-length invariant on `Vec<EnvelopePair>`, so `serde_cbor` accepts the malformed input without error. The attack is deterministic and repeatable with a single HTTP POST.

## Recommendation
Replace the unchecked `updates[0]` with a bounds-checked access that returns an `ApiError` on empty input:

```rust
let first = updates.first().ok_or_else(|| {
    ApiError::invalid_request("SignedTransaction request has no envelope pairs")
})?;
match first.update.content.clone() {
    HttpCallContent::Call { update } => (request_type.clone(), update),
}
```

Additionally, add a validation step in `TryFrom<ConstructionParseRequest> for ParsedTransaction` (or at the start of `construction_parse`) that rejects any `SignedTransaction` where any `Vec<EnvelopePair>` is empty, returning an `ApiError::invalid_request` rather than panicking.

## Proof of Concept
Minimal Rust unit test (can be added to the existing `#[cfg(test)]` block in `construction_parse.rs`):

```rust
#[test]
fn test_empty_envelope_pair_vec_does_not_panic() {
    use crate::models::{SignedTransaction, ConstructionParseRequest};
    use crate::request_types::RequestType;

    // Construct a SignedTransaction with one request having an empty Vec<EnvelopePair>
    let signed_tx = SignedTransaction {
        requests: vec![(RequestType::Send, vec![])],
    };
    let tx_hex = signed_tx.to_string(); // CBOR-hex encode

    let req = ConstructionParseRequest {
        network_identifier: /* valid network id */,
        signed: true,
        transaction: tx_hex,
    };

    // Must return Err(ApiError), not panic
    let result = handler.construction_parse(req);
    assert!(result.is_err(), "Expected ApiError for empty EnvelopePair vec, got panic or Ok");
}
```

Alternatively, a Python integration test using any CBOR library to POST `{"requests": [["Send", []]]}` (CBOR-encoded, hex-stringified) to `/construction/parse` with `signed: true` and assert the response is HTTP 4xx, not a connection reset.

### Citations

**File:** rs/rosetta-api/icp/src/models.rs (L32-58)
```rust
#[derive(Clone, Eq, PartialEq, Debug, Deserialize, Serialize)]
pub struct SignedTransaction {
    pub requests: Vec<Request>,
}

impl FromStr for SignedTransaction {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        let bytes = hex::decode(s).map_err(|err| format!("{err:?}"))?;
        serde_cbor::from_slice(bytes.as_slice()).or_else(|first_err| {
            serde_cbor::from_slice::<LegacySignedTransaction>(bytes.as_slice())
                .map(|legacy_requests| SignedTransaction {
                    requests: legacy_requests,
                })
                .map_err(|_| format!("{first_err:?}"))
        })
    }
}
impl std::fmt::Display for SignedTransaction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", hex::encode(serde_cbor::to_vec(self).unwrap()))
    }
}

/// A vector of update/read-state calls for different ingress windows
/// of the same call.
pub type Request = (RequestType, Vec<EnvelopePair>);
```

**File:** rs/rosetta-api/icp/src/models.rs (L180-197)
```rust
impl TryFrom<ConstructionParseRequest> for ParsedTransaction {
    type Error = ApiError;
    fn try_from(value: ConstructionParseRequest) -> Result<Self, Self::Error> {
        if value.signed {
            Ok(ParsedTransaction::Signed(
                serde_cbor::from_slice(&from_hex(&value.transaction)?).map_err(|e| {
                    ApiError::invalid_request(format!("Could not decode signed transaction: {e}"))
                })?,
            ))
        } else {
            Ok(ParsedTransaction::Unsigned(
                serde_cbor::from_slice(&from_hex(&value.transaction)?).map_err(|e| {
                    ApiError::invalid_request(format!("Could not decode unsigned transaction: {e}"))
                })?,
            ))
        }
    }
}
```

**File:** rs/rosetta-api/icp/src/request_handler/construction_parse.rs (L37-48)
```rust
        let updates: Vec<_> = match ParsedTransaction::try_from(msg.clone())? {
            ParsedTransaction::Signed(signed_transaction) => signed_transaction
                .requests
                .iter()
                .map(
                    |(request_type, updates)| match updates[0].update.content.clone() {
                        HttpCallContent::Call { update } => (request_type.clone(), update),
                    },
                )
                .collect(),
            ParsedTransaction::Unsigned(unsigned_transaction) => unsigned_transaction.updates,
        };
```

**File:** rs/rosetta-api/icp/src/rosetta_server.rs (L115-122)
```rust
#[post("/construction/parse")]
async fn construction_parse(
    msg: web::Json<ConstructionParseRequest>,
    req_handler: web::Data<RosettaRequestHandler>,
) -> HttpResponse {
    let res = req_handler.construction_parse(msg.into_inner());
    to_rosetta_response(res, &req_handler.rosetta_metrics())
}
```
