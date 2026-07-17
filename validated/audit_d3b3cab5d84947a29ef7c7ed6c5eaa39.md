I have all the evidence needed. Let me compile the findings.

### Title
`GetNextLightClientBlock` Returns `prev_state_root = CryptoHash::default()` for Spice Blocks, Corrupting Light Client Proof State — (`core/primitives/src/block.rs` / `chain/chain/src/lightclient.rs`)

---

### Summary

When the Spice protocol feature is enabled, every block header is produced with `prev_state_root = CryptoHash::default()` (all-zero hash) as an explicit placeholder. The `next_light_client_block` RPC handler (`Handler<GetNextLightClientBlock>`) has no Spice-aware workaround and passes this placeholder directly into the returned `LightClientBlockView.inner_lite.prev_state_root`. A light client that accepts this view stores an all-zero state root and can never successfully verify any trie proof against it.

---

### Finding Description

**Step 1 — Spice block production sets `prev_state_root = CryptoHash::default()`**

In `Block::produce` (`core/primitives/src/block.rs`):

```rust
let prev_state_root = if spice_info.is_some() {
    // TODO(spice): include state root from the relevant previous executed block.
    CryptoHash::default()
} else {
    chunks_wrapper.compute_state_root()
};
``` [1](#0-0) 

This placeholder is stored verbatim in `BlockHeaderInnerLite.prev_state_root` and is covered by the block hash / signature, so the block is cryptographically self-consistent.

**Step 2 — `create_light_client_block_view` reads `prev_state_root` without Spice awareness**

In `chain/chain/src/lightclient.rs`:

```rust
let inner_lite_view = BlockHeaderInnerLiteView {
    ...
    prev_state_root: *block_header.prev_state_root(),   // ← CryptoHash::default() for Spice
    ...
};
``` [2](#0-1) 

There is no branch that checks `ProtocolFeature::Spice` or substitutes the last certified state root.

**Step 3 — `Handler<GetNextLightClientBlock>` calls this path unconditionally**

```rust
let ret = Chain::create_light_client_block(
    &head_header,
    self.epoch_manager.as_ref(),
    self.chain.chain_store(),
)?;
``` [3](#0-2) 

No Spice guard exists here.

**Step 4 — The `Status` handler already has the correct workaround, confirming the omission**

```rust
let latest_state_root = if ProtocolFeature::Spice.enabled(head_protocol_version) {
    // Spice block headers carry a placeholder state root since execution is
    // decoupled from consensus. Report the last certified state instead.
    self.client.chain.spice_core_reader
        .last_certified_state_root(head_header.hash())?
        .unwrap_or_default()
} else {
    *head_header.prev_state_root()
};
``` [4](#0-3) 

The `Status` handler explicitly avoids exposing the placeholder. `GetNextLightClientBlock` does not.

**Step 5 — Block validity check skips state root for Spice blocks**

```rust
if !self.is_spice_block() {
    let state_root = self.chunks().compute_state_root();
    if self.header().prev_state_root() != &state_root {
        return Err(InvalidStateRoot);
    }
}
``` [5](#0-4) 

No node-level guard prevents a Spice block from becoming the finalized head and being selected by `create_light_client_block`.

---

### Impact Explanation

A light client that calls `next_light_client_block` against a Spice-enabled node receives a `LightClientBlockView` whose `inner_lite.prev_state_root` is `CryptoHash::default()` (32 zero bytes). Because the block hash is computed over the actual header (which already contains the placeholder), the view passes all signature and stake-threshold checks defined in NEP-25. The light client accepts it as its new head and stores `CryptoHash::default()` as `prev_state_root`. From that point on, every trie proof the light client attempts to verify will fail: no real trie has an all-zero root, so `compute_root(leaf, proof) != CryptoHash::default()` for any valid proof. The light client's proof-verification capability is permanently broken until it re-bootstraps.

---

### Likelihood Explanation

The issue is triggered whenever `ProtocolFeature::Spice` is enabled and a Spice block reaches finality (i.e., becomes `last_final_block` of the chain head). Any unprivileged RPC client calling `next_light_client_block` at that point receives the corrupted view. No special privileges, keys, or network position are required.

---

### Recommendation

Apply the same Spice-aware substitution used in the `Status` handler to `create_light_client_block_view` (or to `Chain::create_light_client_block` / `Handler<GetNextLightClientBlock>`):

```rust
let prev_state_root = if ProtocolFeature::Spice.enabled(protocol_version) {
    spice_core_reader
        .last_certified_state_root(block_header.hash())?
        .unwrap_or_default()
} else {
    *block_header.prev_state_root()
};
```

Alternatively, resolve the `TODO(spice)` in `Block::produce` so that Spice block headers carry the actual certified state root rather than a placeholder, which would fix both this path and any other consumer of `prev_state_root()`.

---

### Proof of Concept

A test-loop test with Spice enabled:

1. Start a test-loop network with `ProtocolFeature::Spice` enabled.
2. Wait for at least one Spice block to reach finality (i.e., `last_final_block` of the head is a Spice block).
3. Call `GetNextLightClientBlock` with the genesis block hash.
4. Assert `ret.inner_lite.prev_state_root != CryptoHash::default()`.

The assertion will fail, confirming the corrupted value is returned to the caller.

### Citations

**File:** core/primitives/src/block.rs (L252-257)
```rust
        let prev_state_root = if spice_info.is_some() {
            // TODO(spice): include state root from the relevant previous executed block.
            CryptoHash::default()
        } else {
            chunks_wrapper.compute_state_root()
        };
```

**File:** core/primitives/src/block.rs (L607-612)
```rust
        if !self.is_spice_block() {
            let state_root = self.chunks().compute_state_root();
            if self.header().prev_state_root() != &state_root {
                return Err(InvalidStateRoot);
            }
        }
```

**File:** chain/chain/src/lightclient.rs (L39-49)
```rust
    let inner_lite_view = BlockHeaderInnerLiteView {
        height: block_header.height(),
        epoch_id: block_header.epoch_id().0,
        next_epoch_id: block_header.next_epoch_id().0,
        prev_state_root: *block_header.prev_state_root(),
        outcome_root: *block_header.outcome_root(),
        timestamp: block_header.raw_timestamp(),
        timestamp_nanosec: block_header.raw_timestamp(),
        next_bp_hash: *block_header.next_bp_hash(),
        block_merkle_root: *block_header.block_merkle_root(),
    };
```

**File:** chain/client/src/view_client_actor.rs (L1104-1110)
```rust
            let ret = Chain::create_light_client_block(
                &head_header,
                self.epoch_manager.as_ref(),
                self.chain.chain_store(),
            )?;

            if ret.inner_lite.height <= last_height { Ok(None) } else { Ok(Some(Arc::new(ret))) }
```

**File:** chain/client/src/client_actor.rs (L799-809)
```rust
        let latest_state_root = if ProtocolFeature::Spice.enabled(head_protocol_version) {
            // Spice block headers carry a placeholder state root since execution is
            // decoupled from consensus. Report the last certified state instead.
            self.client
                .chain
                .spice_core_reader
                .last_certified_state_root(head_header.hash())?
                .unwrap_or_default()
        } else {
            *head_header.prev_state_root()
        };
```
