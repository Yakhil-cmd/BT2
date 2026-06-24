Audit Report

## Title
Unbounded O(N×M) Nested Loop in `construction_combine` Enables Single-Request Memory Exhaustion DoS — (`rs/rosetta-api/icp/src/request_handler/construction_combine.rs`)

## Summary
The `construction_combine` handler iterates over all `updates` (N) × all `ingress_expiries` (M) with no bounds on either dimension. An unauthenticated attacker can craft a single ≤4 MB request containing N identical updates and M expiries, triggering N×M loop iterations each performing heap allocations, cloning, SHA-256 hashing, and DER encoding. The resulting `requests` vector can grow to tens of gigabytes, exhausting the Rosetta process memory. The Rosetta API is an in-scope financial integration component.

## Finding Description
The outer loop at line 41 iterates over `unsigned_transaction.updates` and the inner loop at line 44 iterates over `unsigned_transaction.ingress_expiries`:

```rust
for (request_type, update) in unsigned_transaction.updates {
    let mut request_envelopes = vec![];
    for ingress_expiry in &unsigned_transaction.ingress_expiries {
```

`UnsignedTransaction` is a plain CBOR-deserialized struct with no length constraints on either field:

```rust
pub struct UnsignedTransaction {
    pub updates: Vec<(RequestType, HttpCanisterUpdate)>,
    pub ingress_expiries: Vec<u64>,
}
```

Each inner iteration performs: `update.clone()` (line 45), `make_read_state_from_update` with SHA-256 hashing (line 48), two `der_encode_pk`/`hex_decode_pk` round-trips (lines 70–83, 119–132), and two `HttpRequestEnvelope` heap allocations pushed into `request_envelopes` (line 164).

**Amplification trick:** `update.id()` is derived from `representation_independent_hash()`, which includes `ingress_expiry` but not the position in the `updates` vector. Therefore N *identical* `HttpCanisterUpdate` entries all produce the same `update.id()` for a given expiry. The `HashMap` lookup at line 50–51 succeeds for all N updates using only M distinct transaction signatures and M distinct read-state signatures — 2×M total signatures in the request body.

**Budget within the 4 MB body limit** (`JsonConfig::limit(4 * 1024 * 1024)` at `rosetta_server.rs` line 298): N=28,000 identical updates (~3.4 MB CBOR+hex) and M=1,000 expiries (~16 KB) plus 2,000 signatures (~500 KB) fits within 4 MB. This yields ~28 million inner-loop iterations. Each `EnvelopePair` output is ~510 bytes, so the `requests` vector alone reaches ~14 GB before serialization.

The only guard is the 4 MB JSON body limit. There is no cap on `updates.len()`, `ingress_expiries.len()`, their product, per-request timeout, or concurrency limit on the `/construction/combine` route.

## Impact Explanation
A single crafted request OOMs the Rosetta process or saturates one CPU core until OOM. Because Rosetta is a single-process service with no per-request resource accounting on this endpoint, one request is sufficient to render the node unavailable. This constitutes an application-level DoS of the Rosetta API, a listed in-scope financial integration component, with concrete harm to users relying on it for ICP transaction submission. This matches the **High ($2,000–$10,000)** impact class: "Application/platform-level DoS" and "Significant Rosetta … security impact with concrete user or protocol harm."

## Likelihood Explanation
The endpoint is unauthenticated and publicly reachable. The attack requires only the ability to send an HTTP POST to `/construction/combine`. No key material, governance access, or network-level privilege is needed. The crafted payload is trivially constructable using standard CBOR and JSON libraries. The attack is repeatable and requires no victim interaction.

## Recommendation
1. Add hard caps on `updates` and `ingress_expiries` lengths immediately after deserialization (e.g., `updates.len() ≤ 50`, `ingress_expiries.len() ≤ 200`).
2. Add a product cap: reject if `updates.len() * ingress_expiries.len() > 10_000`.
3. Move `der_encode_pk`/`hex_decode_pk` outside the inner loop — the public key is constant across all iterations.
4. Consider a per-request timeout or memory budget at the actix-web middleware layer for construction endpoints.

## Proof of Concept
```python
import cbor2, json, requests as http

update = {
    "canister_id": b"\x00" * 8,
    "method_name": "x",
    "arg": b"",
    "sender": b"\x04",
    "ingress_expiry": 0,
    "request_type": "call",
}

N, M = 28_000, 1_000
unsigned_tx = {
    "updates": [["Send", update]] * N,
    "ingress_expiries": list(range(M)),
}
unsigned_tx_hex = cbor2.dumps(unsigned_tx).hex()

signatures = []
for _ in range(2 * M):
    signatures.append({
        "signing_payload": {"hex_bytes": "aa" * 32},
        "public_key": {"hex_bytes": "bb" * 32, "curve_type": "edwards25519"},
        "hex_bytes": "cc" * 64,
        "signature_type": "ed25519",
    })

payload = {
    "network_identifier": {"blockchain": "Internet Computer", "network": "00"},
    "unsigned_transaction": unsigned_tx_hex,
    "signatures": signatures,
}

# Single request → Rosetta OOM
http.post("http://<rosetta-node>:8080/construction/combine", json=payload, timeout=300)
```

Expected result: Rosetta process is killed by OOM or becomes unresponsive before returning a response. The payload size stays within the 4 MB JSON body limit.