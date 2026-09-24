No vulnerability found for this question.

The advisory concerns the `lru` crate (jeromefroe/lru-rs), which has a use-after-free bug in its `pop()`/iterator APIs. This codebase does not use that crate at all — all the LRU caches found in production code (e.g., `polkadot/node/core/runtime-api/src/cache.rs`, `polkadot/node/subsystem-util/src/runtime/mod.rs`, `substrate/client/db/src/pinned_blocks_cache.rs`, `substrate/client/executor/src/wasm_runtime.rs`, `substrate/primitives/blockchain/src/header_metadata.rs`, `substrate/primitives/trie/src/cache/`, `substrate/client/rpc-spec-v2/src/chain_head/chain_head_follow.rs`) rely on `schnellru::LruMap`, a different, independently-implemented crate with a different API surface and no relation to the reported `lru`/RUSTSEC-2021-0130 defect. [1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3) [5](#0-4) 

No occurrence of `use lru::` or `lru::LruCache` (the actually-vulnerable crate/API) was found anywhere in the repository, and no dependency declaration for the `lru` crate itself was located in the workspace manifests. Since the vulnerable crate is not even a dependency of the production code, there is no reachable analog through any signed extrinsic, XCM message, or other real user entry point — this is not a dependency-only false positive worth reporting per the exclusion criteria in the method (tests/mocks/generated/config-only/dependency-only findings are rejected, and here there isn't even a dependency present).

### Citations

**File:** polkadot/node/core/runtime-api/src/cache.rs (L40-41)
```rust
pub(crate) struct RequestResultCache {
	authorities: LruMap<Hash, Vec<AuthorityDiscoveryId>>,
```

**File:** polkadot/node/subsystem-util/src/runtime/mod.rs (L79-79)
```rust
	session_index_cache: LruMap<Hash, SessionIndex>,
```

**File:** substrate/client/db/src/pinned_blocks_cache.rs (L19-19)
```rust
use schnellru::{Limiter, LruMap};
```

**File:** substrate/client/executor/src/wasm_runtime.rs (L176-176)
```rust
	runtimes: Mutex<LruMap<VersionedRuntimeId, Arc<VersionedRuntime>>>,
```

**File:** substrate/primitives/blockchain/src/header_metadata.rs (L22-22)
```rust
use schnellru::{ByLength, LruMap};
```
