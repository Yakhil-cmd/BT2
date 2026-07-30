[1](#0-0)

### Citations

**File:** crates/sui-core/src/checkpoints/checkpoint_executor/mod.rs (L455-457)
```rust
        self.epoch_store
            .handle_finalized_checkpoint(&ckpt_state.data.checkpoint, &ckpt_state.data.tx_digests)
            .expect("cannot fail");
```
