Audit Report

## Title
Missing `http2_max_header_list_size` on SOCKS Proxy Client Allows Unbounded Header Allocation in HTTPS Outcalls Adapter — (`rs/https_outcalls/adapter/src/rpc_server.rs`)

## Summary
`create_socks_proxy_client` omits the `.http2_max_header_list_size(MAX_HEADER_LIST_SIZE)` call present on the direct client in `CanisterHttp::new`. When an HTTP/2 connection is made through the SOCKS proxy, the `h2` crate uses its default (effectively unlimited) header list size, allowing a canister-controlled malicious server to force the adapter to heap-allocate arbitrarily large header blocks before any application-level check can intervene. Repeated requests can OOM-kill the adapter process, disrupting HTTP outcall processing for all canisters on the affected node.

## Finding Description
In `CanisterHttp::new` (lines 88–90), the direct client is correctly configured:
```rust
let client = Client::builder(TokioExecutor::new())
    .http2_max_header_list_size(MAX_HEADER_LIST_SIZE)  // 52 KB
    .build::<_, Full<Bytes>>(direct_https_connector);
```
In `create_socks_proxy_client` (lines 119–127), the equivalent call is absent:
```rust
Client::builder(TokioExecutor::new()).build::<_, Full<Bytes>>(
    builder.enable_all_versions().wrap_connector(SocksConnector { ... }),
)
```
Without `.http2_max_header_list_size()`, the `h2` crate uses `u32::MAX` as its internal HPACK decoder limit. The SOCKS fallback is triggered automatically (lines 336–365) whenever the direct connection fails — the normal case for IPv4-only targets, since IC replica nodes are IPv6-only. The post-receive check (lines 374–417) compares `headers_size_bytes` against `max_response_size_bytes`, but this executes only after the `h2` layer has already decoded and heap-allocated the full header list. `validate_headers` (lines 483–500) only validates outgoing request headers, not incoming response headers, providing no protection here.

## Impact Explanation
A canister developer can cause the HTTPS outcalls adapter process on any replica node routing their request through a SOCKS proxy to allocate arbitrarily large amounts of heap memory while decoding HTTP/2 response headers from a malicious server. Exhausting adapter process memory causes an OOM kill, disrupting HTTP outcall processing for all canisters on the affected node until the adapter restarts. This matches the allowed High impact: **Application/platform-level DoS, crash, or subnet availability impact not based on raw volumetric DDoS** ($2,000–$10,000).

## Likelihood Explanation
Any canister developer can deploy a canister making HTTP outcalls to a server they control. The SOCKS path is the normal production path for IPv4 targets. The malicious server simply sends an HTTP/2 HEADERS frame with a large HPACK-encoded header block. No special privileges, key material, or network-level attacks are required. The attack is repeatable and low-cost.

## Recommendation
Add `.http2_max_header_list_size(MAX_HEADER_LIST_SIZE)` to the `Client::builder` call in `create_socks_proxy_client`, mirroring the direct client setup:
```rust
Client::builder(TokioExecutor::new())
    .http2_max_header_list_size(MAX_HEADER_LIST_SIZE)
    .build::<_, Full<Bytes>>(
        builder.enable_all_versions().wrap_connector(SocksConnector { ... }),
    )
```

## Proof of Concept
1. Stand up a malicious HTTP/2 TLS server that responds to any request with a HEADERS frame whose HPACK-encoded header list totals >52 KB (e.g., a single header with a 100 KB value).
2. Send an `HttpsOutcallRequest` to the adapter gRPC endpoint targeting an IPv4-only address (forcing SOCKS fallback) pointing at the malicious server.
3. Observe: the SOCKS client decodes and allocates the full header block before any application-level check fires (confirmed by adapter RSS growth), while the direct client would reject at the 52 KB limit.
4. Scale the header size to several hundred MB and repeat requests; observe adapter process OOM kill.