No vulnerability found for this question.

**Analysis:**

The premise doesn't hold up against the actual code paths. Tracing the state-sync chunk-execution admission path in `execution/executor/src/chunk_executor/mod.rs`:

1. **The network-facing entrypoint (`enqueue_chunk_by_execution`) never calls `TransactionSliceMetadata::chunk()`.** It builds a `ChunkToExecute` from `txn_list_with_proof`, and crucially calls `txn_list_with_proof.verify(verified_target_li.ledger_info(), ...)` before doing anything else [1](#0-0) . This cryptographically validates the peer-supplied chunk (including its version range) against a quorum-certified `LedgerInfoWithSignatures`, so an unprivileged peer cannot supply an arbitrary/inverted `{begin, end}` and have it accepted — malformed proofs are rejected here, well before any slice metadata is constructed.

2. **`ChunkToExecute::into_output` (the type actually used for peer-driven state sync execution) passes `TransactionSliceMetadata::unknown()`, not `Chunk{begin, end}`, to the executor** [2](#0-1) . The `debug_assert!`-guarded `TransactionSliceMetadata::chunk()` constructor is simply never invoked on this path, so there is nothing to bypass.

3. **The only call sites that build `TransactionSliceMetadata::chunk(begin_version, end_version)` from computed bounds are in the local replay-verification path** (`remove_and_replay_epoch`/`verify_execution`), and these bounds are derived from a `while batch_begin < end_version` loop invariant [3](#0-2)  and used at [4](#0-3) . `begin_version < end_version` is structurally guaranteed by the loop condition itself — it is not attacker-influenced input that could go inverted.

Because peer-supplied chunk boundaries are validated via ledger-info-signature proof verification before use, and the actual network-facing code path doesn't even construct `Chunk{begin,end}` metadata (it uses `Unknown`), there is no admission path by which an unprivileged state-sync peer can smuggle an inverted or empty `{begin, end}` pair into commit logic to re-admit already-committed transactions. This also falls outside the review's boundary conditions, which explicitly instruct to ignore peer-driven scenarios.

### Citations

**File:** execution/executor/src/chunk_executor/mod.rs (L154-159)
```rust
        if !cfg!(feature = "consensus-only-perf-test") {
            txn_list_with_proof.verify(
                verified_target_li.ledger_info(),
                txn_list_with_proof.get_first_transaction_version(),
            )?;
        }
```

**File:** execution/executor/src/chunk_executor/mod.rs (L593-643)
```rust
        let mut batch_begin = begin_version;
        let mut batch_end = *batch_ends.next().unwrap();
        while batch_begin < end_version {
            if batch_begin == batch_end {
                // batch_end is a known broken version that won't pass execution verification
                self.remove_and_apply(
                    transactions,
                    persisted_aux_info,
                    transaction_infos,
                    write_sets,
                    event_vecs,
                    batch_begin,
                    batch_begin + 1,
                )?;
                chunks_enqueued += 1;
                info!(
                    version_skipped = batch_begin,
                    "Skipped known broken transaction, applied transaction output directly."
                );
                batch_begin += 1;
                batch_end = *batch_ends.next().unwrap();
                continue;
            }

            // Try to run the transactions with the VM
            let next_begin = if verify_execution_mode.should_verify() {
                self.verify_execution(
                    transactions,
                    persisted_aux_info,
                    transaction_infos,
                    write_sets,
                    event_vecs,
                    batch_begin,
                    batch_end,
                    verify_execution_mode,
                )?
            } else {
                batch_end
            };
            self.remove_and_apply(
                transactions,
                persisted_aux_info,
                transaction_infos,
                write_sets,
                event_vecs,
                batch_begin,
                next_begin,
            )?;
            chunks_enqueued += 1;
            batch_begin = next_begin;
        }
```

**File:** execution/executor/src/chunk_executor/mod.rs (L674-683)
```rust
        let onchain_config = chunk_onchain_config(&state_view)?;
        let execution_output = DoGetExecutionOutput::by_transaction_execution::<V>(
            &V::new(),
            txns.into(),
            auxiliary_info,
            &parent_state,
            state_view,
            onchain_config,
            TransactionSliceMetadata::chunk(begin_version, end_version),
        )?;
```

**File:** execution/executor/src/chunk_executor/transaction_chunk.rs (L100-111)
```rust
        DoGetExecutionOutput::by_transaction_execution::<V>(
            &V::new(),
            sig_verified_txns.into(),
            persisted_aux_info
                .into_iter()
                .map(|info| AuxiliaryInfo::new(info, None))
                .collect(),
            parent_state,
            state_view,
            onchain_config,
            TransactionSliceMetadata::unknown(),
        )
```
