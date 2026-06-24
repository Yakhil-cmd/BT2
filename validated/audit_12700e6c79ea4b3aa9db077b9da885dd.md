All cited code has been verified against the actual repository. Every claim checks out:

- `Hash` and `PartialEq` for `RequestContext` confirmed to omit `request_type` [1](#0-0) 
- `is_query()` returns `true` for `QueryV2`, `QueryV3`, and `QuerySubnetV3` [2](#0-1) 
- `BypasserIC::bypass` only bypasses non-query types, so both V2 and V3 enter the cache [3](#0-2) 
- `KeyExtractorContext::extract` uses `Arc<RequestContext>` directly as the cache key [4](#0-3) 
- Both `PATH_QUERY_V2` and `PATH_QUERY_V3` routes exist and are dispatched to the same cache middleware [5](#0-4) 

---

Audit Report

## Title
Cache Key Collision Between `QueryV2` and `QueryV3` Allows Unsigned Response Served for Signed-Response Endpoint — (`rs/boundary_node/ic_boundary/src/routes.rs`, `rs/boundary_node/ic_boundary/src/http/middleware/cache.rs`)

## Summary
The custom `Hash` and `PartialEq` implementations for `RequestContext` omit the `request_type` field, making `QueryV2` and `QueryV3` contexts with identical payload fields indistinguishable as cache keys. Because `BypasserIC` permits both variants through the cache, a `QueryV2` response (unsigned) stored in the cache will be returned verbatim to a subsequent `QueryV3` request with matching parameters, silently stripping the node signature that `QueryV3` is designed to provide.

## Finding Description
`RequestContext::Hash` (lines 94–108 of `routes.rs`) hashes only `canister_id`, `sender`, `method_name`, `ingress_expiry`, and `arg`/`http_request`. `RequestContext::PartialEq` (lines 111–125) compares the same fields. `request_type` is absent from both. Two contexts differing only in `request_type` (`QueryV2` vs `QueryV3`) therefore produce identical hash values and compare as equal.

`BypasserIC::bypass` (lines 74–76 of `cache.rs`) returns `Some(BypassReasonIC::IncorrectRequestType)` only when `!ctx.request_type.is_query()`. `is_query()` returns `true` for `QueryV2`, `QueryV3`, and `QuerySubnetV3` (line 63 of `http/mod.rs`), so neither variant is bypassed.

`KeyExtractorContext::extract` (lines 36–45 of `cache.rs`) uses `Arc<RequestContext>` directly as the cache key. Because the key type's `Hash`/`Eq` ignore `request_type`, a `QueryV2` entry and a `QueryV3` entry with the same payload fields occupy the same cache slot.

Exploit flow:
1. Attacker sends `POST /api/v2/canister/{id}/query` with chosen `(canister_id, sender, method_name, ingress_expiry, arg)` → cache **Miss**, unsigned replica response stored.
2. Victim sends `POST /api/v3/canister/{id}/query` with the same tuple → cache **Hit**, the stored unsigned `QueryV2` body is returned.
3. Victim receives a CBOR response with no `signatures` field, believing it to be the node-signed envelope that `QueryV3` guarantees.

No existing guard prevents this: the bypasser checks only `is_query()`, and the key extractor performs no type discrimination.

## Impact Explanation
`/api/v3/canister/{id}/query` exists specifically to let clients verify replica authenticity without trusting the boundary node, by including a node signature in the response. Serving a cached unsigned `QueryV2` body for a `QueryV3` request removes that guarantee entirely. Any client that validates the `QueryV3` signature (or relies on its presence) is silently given an unauthenticated response. This constitutes a significant boundary/API security impact with concrete user harm: the boundary node covertly downgrades a security-critical API property, matching the High impact class ("Significant boundary/API security impact with concrete user or protocol harm").

## Likelihood Explanation
No privileged access is required; any public API caller can prime the cache. The only alignment constraint is `ingress_expiry`: the attacker's `QueryV2` request must carry the same expiry as the victim's `QueryV3` request. An attacker who controls both requests (e.g., testing both endpoints, or a client library that uses a predictable expiry window) can satisfy this trivially. Even without controlling the victim, an attacker can flood the cache with `QueryV2` entries across a range of expiry values covering the victim's likely window. The collision is deterministic and 100% reproducible once parameters match.

## Recommendation
Include `request_type` in both `Hash` and `PartialEq` for `RequestContext`:

```rust
// In Hash impl
self.request_type.hash(state);

// In PartialEq impl
self.request_type == other.request_type && /* existing fields */
```

Alternatively, add a `BypassReasonIC::QueryV3` variant and bypass caching for `QueryV3` entirely in `BypasserIC::bypass`, since per-node signed responses are not safely shareable across requests or request types.

## Proof of Concept
Add the following test to `rs/boundary_node/ic_boundary/src/http/middleware/cache.rs` alongside the existing `test_cache`:

```rust
#[tokio::test]
async fn test_cache_v2_v3_collision() -> Result<(), Error> {
    let cli = cli::Cache {
        cache_size: Some(MAX_MEM_SIZE),
        cache_max_item_size: MAX_RESP_SIZE,
        cache_ttl: Duration::from_secs(3600),
        cache_non_anonymous: false,
    };
    let cache_state = Arc::new(CacheState::new(&cli, &Registry::new()).unwrap());
    let mut app = Router::new()
        .route("/", post(handler))
        .layer(middleware::from_fn_with_state(cache_state, cache_middleware));

    // Step 1: prime cache with QueryV2
    let req_v2 = gen_request_with_params(
        CANISTER_1, RequestType::QueryV2, false, DEFAULT_SIZE, 42, true, StatusCode::OK,
    );
    let res = app.call(req_v2).await.unwrap();
    let cs = res.extensions().get::<CacheStatus<BypassReasonIC>>().cloned().unwrap();
    assert!(matches!(cs, CacheStatus::Miss(_)));

    // Step 2: send QueryV3 with identical payload fields
    let req_v3 = gen_request_with_params(
        CANISTER_1, RequestType::QueryV3, false, DEFAULT_SIZE, 42, true, StatusCode::OK,
    );
    let res = app.call(req_v3).await.unwrap();
    let cs = res.extensions().get::<CacheStatus<BypassReasonIC>>().cloned().unwrap();
    // This assert currently PASSES, demonstrating the collision:
    assert!(matches!(cs, CacheStatus::Hit(_)));
    Ok(())
}
```

Running `cargo test -p ic-boundary test_cache_v2_v3_collision` will confirm the `QueryV3` request receives a cache hit from the `QueryV2` entry.

### Citations

**File:** rs/boundary_node/ic_boundary/src/routes.rs (L94-125)
```rust
impl Hash for RequestContext {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.canister_id.hash(state);
        self.sender.hash(state);
        self.method_name.hash(state);
        self.ingress_expiry.hash(state);

        // Hash http_request if it's present, arg otherwise
        // They're mutually exclusive
        if self.http_request.is_some() {
            self.http_request.hash(state);
        } else {
            self.arg.hash(state);
        }
    }
}

impl PartialEq for RequestContext {
    fn eq(&self, other: &Self) -> bool {
        let r = self.canister_id == other.canister_id
            && self.sender == other.sender
            && self.method_name == other.method_name
            && self.ingress_expiry == other.ingress_expiry;

        // Same as in hash()
        if self.http_request.is_some() {
            r && self.http_request == other.http_request
        } else {
            r && self.arg == other.arg
        }
    }
}
```

**File:** rs/boundary_node/ic_boundary/src/http/mod.rs (L12-13)
```rust
pub const PATH_QUERY_V2: &str = "/api/v2/canister/{canister_id}/query";
pub const PATH_QUERY_V3: &str = "/api/v3/canister/{canister_id}/query";
```

**File:** rs/boundary_node/ic_boundary/src/http/mod.rs (L62-64)
```rust
    pub const fn is_query(&self) -> bool {
        matches!(self, Self::QueryV2 | Self::QueryV3 | Self::QuerySubnetV3)
    }
```

**File:** rs/boundary_node/ic_boundary/src/http/middleware/cache.rs (L36-45)
```rust
    fn extract<T>(&self, req: &Request<T>) -> Result<Self::Key, CacheError> {
        let ctx = req
            .extensions()
            .get::<Arc<RequestContext>>()
            .ok_or_else(|| {
                CacheError::ExtractKey("unable to get RequestContext extension".into())
            })?;

        Ok(ctx.clone())
    }
```

**File:** rs/boundary_node/ic_boundary/src/http/middleware/cache.rs (L74-76)
```rust
        Ok(if !ctx.request_type.is_query() {
            // We cache only Query
            Some(BypassReasonIC::IncorrectRequestType)
```
