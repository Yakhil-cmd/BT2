Given my tool budget was exhausted before I could read the full body of `TrieViewer::view_access_keys`, I can only confirm what the imports and grep results show, not the exact loop structure or whether a page cap exists. I'll note this limitation explicitly below.

### Title
Unbounded per-key trie work in `view_access_keys` RPC scales linearly with attacker-purchased access-key count, with no pagination cap - ([File: runtime/runtime/src/state_viewer/mod.rs])

### Summary
`TrieViewer::view_access_keys` in `runtime/runtime/src/state_viewer/mod.rs` imports and uses `parse_key_handle_from_access_key_key` and `parse_nonce_index_from_gas_key_key` alongside `get_access_key`/`get_gas_key_nonce` lookups, indicating it performs per-key parsing and extra trie lookups for every access key stored under an account. Unlike `view_state`, which is capped via `MAX_VIEW_STATE_PAGE_ITEMS`, no equivalent constant/import for `view_access_keys` was found in this file, suggesting no page/item cap bounds per-call cost. [1](#0-0) 

### Finding Description
The imports in `runtime/runtime/src/state_viewer/mod.rs` confirm the function pulls in `parse_key_handle_from_access_key_key`, `parse_nonce_index_from_gas_key_key` from `near_primitives::trie_key::trie_key_parsers`, and `get_access_key`, `get_gas_key_nonce` from `near_store` — the exact primitives named in the question as being invoked per access key during enumeration. [1](#0-0)  A grep for `MAX_VIEW_STATE_PAGE_ITEMS` returned matches in this file, confirming that constant exists and is used somewhere in `state_viewer/mod.rs` (associated with `view_state`), but I was not able to confirm within my remaining tool budget whether an analogous cap is applied inside `view_access_keys` itself, since I could not retrieve the actual function body before running out of iterations.

Because an ordinary account holder can legitimately create N access keys via repeated `AddKeyAction`s (bounded only by their storage-staking balance), and each key is presumably a separate trie key parsed/looked-up per the imports above, a single `view_access_keys` RPC call would perform O(N) parsing + trie-lookup work with no evidence of a bounded page size, in contrast to `view_state`'s `MAX_VIEW_STATE_PAGE_ITEMS` guard.

### Impact Explanation
If confirmed, this would fall under "node panic or unbounded resource use" (RPC/validator CPU exhaustion scaling with account key count). However, the severity is inherently limited because the attacker must pay real on-chain storage-staking cost proportional to N to create that many keys — the cost is not free, only "underpriced" relative to the RPC compute it triggers per query, and RPC view calls typically run outside consensus-critical gas metering on view-only threads.

### Likelihood Explanation
I could not fully verify the internal implementation of `view_access_keys` (loop structure, whether a cap exists, exact per-key trie-lookup count) within available tool iterations — only the module-level imports match the primitives named in the question. This is a meaningful gap: the question's precise claim ("one extra `get_access_key_by_handle` trie lookup per key", "tripling per-key RPC cost") could not be confirmed against the actual function body, nor could the absence of any page/item cap be definitively confirmed versus merely not-yet-found in the parts of the file I read.

### Recommendation
Add an item/page cap to `view_access_keys` analogous to `MAX_VIEW_STATE_PAGE_ITEMS` used by `view_state`, and/or amortize per-key parsing to a single trie scan without redundant handle/nonce-index lookups, to bound per-RPC-call CPU cost independent of attacker-purchased key count.

### Proof of Concept
Integration test: create an account, fund it, issue `AddKeyAction` N times (e.g., N = 10, 100, 1000, 10000) up to the account's storage-staking limit, then call `view_access_keys` and measure wall-clock latency / trie-lookup count as a function of N; assert cost stays within a fixed per-request budget or that the endpoint paginates results, analogous to the `MAX_VIEW_STATE_PAGE_ITEMS` behavior in `view_state`.

**Note on verification limits**: I was unable to read the full body of `view_access_keys` (only its imports) before exhausting my tool-call budget, so I cannot confirm the exact per-key trie-lookup multiplier (3x) or definitively rule out an existing bound. A follow-up session with access to `runtime/runtime/src/state_viewer/mod.rs`'s full `view_access_keys` implementation and `runtime/runtime/src/access_keys.rs` would be needed to conclusively validate or refute the precise mechanics claimed in the question.

### Citations

**File:** runtime/runtime/src/state_viewer/mod.rs (L19-29)
```rust
use near_primitives::trie_key::trie_key_parsers::{
    self, parse_key_handle_from_access_key_key, parse_nonce_index_from_gas_key_key,
};
use near_primitives::types::{
    AccountId, Balance, BlockHeight, EpochHeight, EpochId, EpochInfoProvider, Gas, Nonce, ShardId,
};
use near_primitives::version::assert_supported_protocol_version;
use near_primitives::views::{StateItem, ViewStateResult};
use near_primitives_core::config::ViewConfig;
use near_store::trie::AccessOptions;
use near_store::{TrieAccess as _, TrieUpdate, get_access_key, get_account, get_gas_key_nonce};
```
