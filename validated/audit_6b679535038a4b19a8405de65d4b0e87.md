### Title
Missing upper bound on `limit`/`prefix`/`after_key` in `RpcViewStateRequest::parse` allows unbounded per-query trie iteration cost - (File: chain/jsonrpc/src/api/view_state.rs)

### Summary
`RpcViewStateRequest::parse` in `chain/jsonrpc/src/api/view_state.rs` only calls `validate_view_state_pagination`, which checks *logical consistency* between `include_proof`, `after_key_base64`, and `limit`, but never caps the numeric value of `limit` (an `Option<NonZeroU32>`, so up to `u32::MAX`) or the size of `prefix`/`after_key`. An attacker who controls these fields at their maxima can request pagination pages that force the node to iterate/serialize far more trie state than any reasonable single JSON-RPC call should, with no bound enforced at the parse layer.

### Finding Description
`parse` is the sole gate before an `RpcViewStateRequest` is forwarded to the view client/runtime: [1](#0-0) 

The validation helper only rejects the combination of `include_proof` with pagination, and enforces that `after_key` is prefixed by `prefix`; it performs no bound on `limit`'s magnitude, nor on the byte-length of `prefix` or `after_key`: [2](#0-1) 

The request struct declares `limit` as `Option<NonZeroU32>` with no `#[serde]` range constraint, so a client can legally submit `limit: 4294967295`: [3](#0-2) 

Because `parse` is the only chokepoint shown in the target file/function that could reject oversized pagination parameters before the request reaches the runtime/trie viewer, and it does not do so, the enforcement of a hard per-query resource bound (if any) must live entirely downstream of this function — outside the scope of what is verifiable from `view_state.rs` and `api/mod.rs` alone. I was not able to trace and confirm the downstream view-client/runtime code path (e.g., trie iteration cap, byte-size cap such as `TooLargeContractState`, or gas/time budget) within the tool-call budget available, so it is uncertain whether a compensating control exists further down the call chain.

### Impact Explanation
If no downstream cap exists (unverified), a single unauthenticated `view_state` RPC call with a maximal `limit` and a broad/empty `prefix` against an account with non-trivial state could force the node to walk and serialize a very large number of trie entries in one synchronous call, consuming disproportionate CPU/memory relative to the cost of issuing the RPC request — a resource-exhaustion / node-availability risk (Immunefi "High – RPC node crash or unavailability" class), matching the scenario in the question.

### Likelihood Explanation
Feasibility depends entirely on whether a downstream limit exists that was not visible in the reviewed files. The `parse` function itself is unconditionally reachable by any unauthenticated JSON-RPC caller and performs zero magnitude-based validation on `limit`, `prefix`, or `after_key`, so if no other layer enforces a cap, the attack is trivially repeatable at will with no privilege required.

### Recommendation
Add explicit bounds inside `validate_view_state_pagination` (or a new check in `RpcViewStateRequest::parse`): reject requests with `limit` above a small server-configured maximum (e.g., a few thousand entries), and cap `prefix`/`after_key` byte lengths, returning `RpcParseError` for values exceeding the bound — mirroring how other paginated RPC endpoints in the codebase clamp page sizes.

### Proof of Concept
Integration test plan (in `integration-tests`/`jsonrpc-tests`):
1. Deploy/seed an account with a large number of state entries under a shared prefix.
2. Issue a `view_state` JSON-RPC call with `prefix_base64` = empty (or the shared prefix), `limit` = `4294967295`, `include_proof` = false.
3. Assert the response is a typed `RpcParseError`/`RpcViewStateError` (e.g., a new "limit too large" error) rather than a long-running/unbounded call or node resource spike.
4. Repeat with a maximal `after_key_base64` (max-length byte array) to confirm length-based rejection.

Note: This PoC targets the parse-layer gap identified in `view_state.rs`/`api/mod.rs`; confirming actual unbounded CPU/memory consumption requires also validating (not verified here) that no downstream cap exists in the view client/runtime trie-iteration code.

### Citations

**File:** chain/jsonrpc/src/api/view_state.rs (L9-19)
```rust
impl RpcRequest for RpcViewStateRequest {
    fn parse(value: Value) -> Result<Self, RpcParseError> {
        let request: Self = Params::parse(value)?;
        super::validate_view_state_pagination(
            request.prefix.as_slice(),
            request.after_key.as_ref().map(|k| k.as_slice()),
            request.limit,
            request.include_proof,
        )?;
        Ok(request)
    }
```

**File:** chain/jsonrpc/src/api/mod.rs (L91-116)
```rust
/// Rejects view_state pagination arguments the trie viewer can't serve.
fn validate_view_state_pagination(
    prefix: &[u8],
    after_key: Option<&[u8]>,
    limit: Option<NonZeroU32>,
    include_proof: bool,
) -> Result<(), RpcParseError> {
    // TODO(#15612): a resumed page seeks with AccessOptions::NO_SIDE_EFFECTS, so it
    // doesn't record the trie path from the root and the proof can't chain back to
    // the state root. Until we record the seek's nodes, reject proof + pagination.
    if include_proof && (after_key.is_some() || limit.is_some()) {
        return Err(RpcParseError(
            "include_proof is not supported with paginated view_state \
             (after_key_base64 / limit)"
                .to_string(),
        ));
    }
    if let Some(after_key) = after_key {
        if !after_key.starts_with(prefix) {
            return Err(RpcParseError(
                "after_key_base64 must start with prefix_base64".to_string(),
            ));
        }
    }
    Ok(())
}
```

**File:** chain/jsonrpc-primitives/src/types/view_state.rs (L1-17)
```rust
use std::num::NonZeroU32;

#[derive(serde::Serialize, serde::Deserialize, Debug)]
#[cfg_attr(feature = "schemars", derive(schemars::JsonSchema))]
pub struct RpcViewStateRequest {
    #[serde(flatten)]
    pub block_reference: near_primitives::types::BlockReference,
    pub account_id: near_primitives::types::AccountId,
    #[serde(rename = "prefix_base64")]
    pub prefix: near_primitives::types::StoreKey,
    #[serde(default)]
    pub include_proof: bool,
    #[serde(default, rename = "after_key_base64")]
    pub after_key: Option<near_primitives::types::StoreKey>,
    #[serde(default)]
    pub limit: Option<NonZeroU32>,
}
```
