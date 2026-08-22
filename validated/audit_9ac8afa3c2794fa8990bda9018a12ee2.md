### Title
`view_state` byte-cap check runs before item append, allowing a single oversized value to blow past `MAX_VIEW_STATE_PAGE_BYTES` per RPC call - (File: runtime/runtime/src/state_viewer/mod.rs)

### Summary
In `TrieViewer::view_state`, the per-page byte cap (`MAX_VIEW_STATE_PAGE_BYTES = 50_000`) is checked with `hit_bytes = used_bytes >= cap` **before** the current item is appended to `values`, not after. An attacker who stores one large value under their own account and then calls `view_state` with `limit=1` can have that single oversized item pushed into `values` and returned in one response, since the check only stops *future* items, not the one currently being processed.

### Finding Description
The relevant code is:
```rust
let hit_items = item_cap.is_some_and(|cap| values.len() as u64 >= u64::from(cap));
let hit_bytes = byte_cap.is_some_and(|cap| used_bytes >= cap);
if hit_items || hit_bytes {
    last_key = values.last().map(|it: &StateItem| it.key.clone());
    break;
}
used_bytes += (key.len() + value.len()) as u64;
values.push(StateItem { key: key[acc_sep_len..].to_vec().into(), value: value.into() });
``` [1](#0-0) 

`used_bytes` starts at 0 and is only incremented *after* an item is accepted, so the very first item of a page is always admitted regardless of its size — the cap only prevents a *second* item from being added once the accumulated size reaches 50,000 bytes. The code comment even acknowledges this design: "The byte cap is soft: it's checked before each append, so a page can run one item over." [2](#0-1) 

An unprivileged account holder can:
1. Submit a `Stake`/`FunctionCall` action (or a contract call performing `storage_write`) that stores a value close to the protocol's configured `max_length_storage_value` under its own account's contract storage.
2. Repeatedly call the `view_state` (query RPC `view_state`) endpoint with `prefix` matching that key and `limit=1`.
3. Each call returns/allocates a single `StateItem` whose value size is bounded only by the runtime's configured `max_length_storage_value` (not by `MAX_VIEW_STATE_PAGE_BYTES`), because the byte check happens before, not after, the append.

The `item_cap` (`MAX_VIEW_STATE_PAGE_ITEMS = 10_000`) is not violated (only one item is returned when `limit=1`), so this is purely a byte-size soft-cap bypass, not an item-count bypass.

### Impact Explanation
Each `view_state` call is intended to bound response/allocation size to ~50KB per page via `MAX_VIEW_STATE_PAGE_BYTES`. Because the check precedes the append, an attacker can force a single call to return/allocate a value up to the protocol's `max_length_storage_value` limit (a value substantially larger than 50,000 bytes, though still capped by that separate protocol parameter, not literally unbounded). Repeated calls from an unprivileged account to a public RPC node can be used to increase per-request memory allocation and network egress on validator/RPC nodes beyond the intended per-page soft cap, contributing to resource-exhaustion pressure on the node serving the query. This maps to the "node panic or unbounded resource use" bounty class, though the resource growth is bounded by the existing storage-value-size limit rather than being truly unbounded.

### Likelihood Explanation
Highly likely to be reproducible: it requires only (a) an ordinary account able to write to its own contract storage a value near the maximum allowed storage value size, and (b) calling the public `view_state` query RPC with `limit=1` against that account/prefix. No special permissions, races, or protocol-version gating are needed; the check ordering is deterministic and always triggers on the first oversized item of a page.

### Recommendation
Move the byte-cap check to occur before pushing an item but re-check against the *prospective* size, i.e., only append if `used_bytes + item_size <= cap`, or accept the first item unconditionally but reject growth strictly (append the current item, then break if `used_bytes > cap`, i.e., move the increment before the check so the check reflects the post-append size for the *next* iteration, and additionally reject/skip appending an item if its own size alone exceeds the byte cap, splitting it out with a `last_key` continuation to avoid a single oversized item being force-returned).

### Proof of Concept
Unit test plan in `runtime/runtime/src/state_viewer/mod.rs` test module:
1. Set up a `TrieUpdate` with an account and one contract-storage key whose value length is, e.g., 200,000 bytes (or the configured `max_length_storage_value`), well above `MAX_VIEW_STATE_PAGE_BYTES = 50_000`.
2. Call `TrieViewer::view_state(state_update, &account_id, prefix, None, Some(NonZeroU32::new(1).unwrap()), false)`.
3. Assert `result.values.len() == 1` and `result.values[0].value.len() > 50_000`, demonstrating that `used_bytes` after the (only) append exceeds `MAX_VIEW_STATE_PAGE_BYTES` by the full size of the oversized value, confirming the soft cap is bypassed on the very first item of every page.

### Citations

**File:** runtime/runtime/src/state_viewer/mod.rs (L280-283)
```rust
        // Per-page caps, separate from the `trie_viewer_state_size_limit` that pagination skips.
        // The byte cap is soft: it's checked before each append, so a page can run one item over.
        const MAX_VIEW_STATE_PAGE_ITEMS: u32 = 10_000;
        const MAX_VIEW_STATE_PAGE_BYTES: u64 = 50_000;
```

**File:** runtime/runtime/src/state_viewer/mod.rs (L308-317)
```rust
            let hit_items = item_cap.is_some_and(|cap| values.len() as u64 >= u64::from(cap));
            let hit_bytes = byte_cap.is_some_and(|cap| used_bytes >= cap);
            if hit_items || hit_bytes {
                // At least one more item exists; resume after the last we kept.
                last_key = values.last().map(|it: &StateItem| it.key.clone());
                break;
            }
            used_bytes += (key.len() + value.len()) as u64;
            values.push(StateItem { key: key[acc_sep_len..].to_vec().into(), value: value.into() });
        }
```
