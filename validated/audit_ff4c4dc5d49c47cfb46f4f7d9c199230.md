## Finding

### Title
Unbounded, unrate-limited transaction validation in the public JSON-RPC endpoint enables a DoS via repeated signature/state verification - (File: `chain/client/src/rpc_handler.rs`, `chain/jsonrpc/src/lib.rs`)

### Summary
The external report describes `DisperseBlobAuthenticated` performing expensive challenge/signature verification for every incoming request before any rate limiting is applied, letting an attacker force unbounded CPU/DB work with no throttling. nearcore has a directly analogous, reachable path: the public JSON-RPC transaction-submission methods (`broadcast_tx_async`, `broadcast_tx_commit`, `send_tx`) accept arbitrary `SignedTransaction`s from anyone and route them to `RpcHandlerActor::process_tx_internal`, which performs Ed25519/secp256k1/ML-DSA signature verification and one or more trie/state reads (account + access key lookup, balance/allowance/storage-stake computation) for *every* submitted transaction — before the only capacity limit (the transaction pool size cap) is ever consulted.

### Finding Description
`process_tx_internal` in [1](#0-0)  runs, per incoming transaction:
1. A cheap validity-period check.
2. `self.runtime.validate_tx(...)`, which calls `ValidatedTransaction::new`, performing full cryptographic signature verification: [2](#0-1) .
3. If the node tracks the shard, `self.runtime.can_verify_and_charge_tx(...)`, which loads the trie for the shard, fetches the signer account and access key from state, and runs full balance/allowance/storage-stake verification: [3](#0-2) .

Only *after* all of this expensive work does the code check the transaction pool size limit inside `pool.insert_transaction(...)`: [4](#0-3) . Crucially, that size-based rejection only ever runs for a node that `is_chunk_producer_for_transaction` — for any other node (the common case for public RPC endpoints operated by infra providers), there is no capacity check at all after the expensive verification: [5](#0-4) .

At the HTTP layer, the JSON-RPC server (`chain/jsonrpc/src/lib.rs`) applies only a body-size limit and CORS policy as middleware — there is no per-origin/per-IP/per-account rate limiter guarding calls into `process_tx`: [6](#0-5) . The architecture doc for this module explicitly states the design intent: `RpcHandlerActor` exists "to keep transaction validation work (signature checks, nonce lookups, balance verification) off the consensus-critical `ClientActor`" — acknowledging the cost of this work but providing no rate limiting for it: [7](#0-6) .

This mirrors the reported bug class precisely: an unauthenticated caller can trigger repeated expensive authentication/verification work (crypto signature checks + trie state reads) with the only throttling mechanism (pool size, and even then only for chunk producers) applied *after* the expensive work has already been done, and with no origin-based rate limiting anywhere in the request path.

### Impact Explanation
An attacker can flood a node's public RPC endpoint (`broadcast_tx_async`/`broadcast_tx_commit`) with a large volume of syntactically valid but otherwise garbage `SignedTransaction`s (invalid nonce, insufficient balance, bad receiver, etc.). Each request forces the node's `RpcHandlerActor` threads to perform full signature verification and multiple trie lookups before rejecting the transaction. Since `RpcHandlerActor` is intentionally isolated to offload this cost from `ClientActor`, an attacker cannot directly stall consensus, but they can exhaust the handler thread pool and the underlying storage/DB I/O capacity of the node, degrading or denying RPC service (including legitimate transaction submission) — a node availability/DoS impact reachable purely from unauthenticated external JSON-RPC requests, with no on-chain cost to the attacker (invalid transactions never touch balances or gas).

### Likelihood Explanation
High. `broadcast_tx_async` requires no authentication, no gas payment, and no valid nonce/balance — the attacker only needs to construct a structurally valid (but semantically invalid) signed transaction referencing any account/key, which is trivial and free to generate in bulk. There is no rate limiting, CAPTCHA, or per-origin throttling anywhere between the HTTP layer and the expensive verification code.

### Recommendation
Add request-level rate limiting to the JSON-RPC transaction-submission path (`process_tx`/`send_tx_async`/`send_tx`), scoped by client IP/origin or connection, applied *before* signature verification and trie lookups are performed. Consider also adding a lightweight pre-check (e.g., a cheap format/duplicate-hash check) ahead of the costly signature and state verification steps, and extending the transaction-pool capacity check (`chain/pool/src/lib.rs`) so it isn't skipped for nodes that aren't chunk producers for the transaction's shard.

### Proof of Concept
1. Stand up a nearcore node with the public JSON-RPC server enabled (default config, port 3030).
2. Script a client that repeatedly POSTs `broadcast_tx_async` requests with freshly generated `SignedTransaction`s (random keypairs, arbitrary nonce/receiver, valid Borsh encoding and Ed25519 signature over the transaction hash — this is required so `ValidatedTransaction::new`'s signature check passes and the trie-lookup path in `can_verify_and_charge_tx` is reached, per [2](#0-1) ).
3. Observe that each request causes a signature verification and one-or-more trie state reads inside `process_tx_internal` ( [8](#0-7) ) with no throttling; sustained request volume saturates `handler_threads` and backing storage I/O, degrading RPC responsiveness for legitimate users.

### Citations

**File:** chain/client/src/rpc_handler.rs (L151-273)
```rust
    fn process_tx_internal(
        &self,
        signed_tx: &SignedTransaction,
        is_forwarded: bool,
        check_only: bool,
    ) -> Result<ProcessTxResponse, near_client_primitives::types::Error> {
        let head = self.chain_store.head()?;
        let signer = self.validator_signer.get();
        let me = signer.as_ref().map(|vs| vs.validator_id());
        let cur_block = self.chain_store.get_block(&head.last_block_hash)?;
        let cur_block_header = cur_block.header();
        // here it is fine to use `cur_block_header` as it is a best effort estimate. If the transaction
        // were to be included, the block that the chunk points to will have height >= height of
        // `cur_block_header`.
        if let Err(e) = check_transaction_validity_period(
            &self.chain_store,
            &cur_block_header,
            signed_tx.transaction.block_hash(),
            self.config.transaction_validity_period,
        ) {
            tracing::debug!(target: "client", ?signed_tx, "invalid tx: expired or from a different fork");
            return Ok(ProcessTxResponse::InvalidTx(e));
        }
        let gas_price = cur_block_header.next_gas_price();
        let epoch_id = self.epoch_manager.get_epoch_id_from_prev_block(&head.last_block_hash)?;
        let protocol_version = self.epoch_manager.get_epoch_protocol_version(&epoch_id)?;
        let shard_layout = self.epoch_manager.get_shard_layout(&epoch_id)?;
        let receiver_shard =
            shard_layout.account_id_to_shard_id(signed_tx.transaction.receiver_id());
        // TODO(spice): get_last_certified_block_header does multiple DB reads
        // (loading uncertified chunks + block headers). Cache the last certified
        // block header for the current head, or store the last-certified hash in
        // chain state so this is O(1).
        let spice_certified_header = if ProtocolFeature::Spice.enabled(protocol_version) {
            Some(get_last_certified_block_header(&self.chain_store, &head.last_block_hash)?)
        } else {
            None
        };

        let receiver_congestion_info = if let Some(certified_header) = &spice_certified_header {
            // Receiver-shard congestion from the last certified block's executed
            // ChunkExtras, to reject transactions to a congested shard.
            spice_shard_congestion_info(
                &self.chain_store,
                &shard_layout,
                certified_header.as_ref(),
                receiver_shard,
            )
        } else {
            cur_block.block_congestion_info().get(&receiver_shard).copied()
        };

        let validated_tx = match self.runtime.validate_tx(
            &shard_layout,
            signed_tx.clone(),
            protocol_version,
            receiver_congestion_info,
        ) {
            Ok(validated_tx) => validated_tx,
            Err((err, signed_tx)) => {
                tracing::debug!(target: "client", tx_hash = ?signed_tx.get_hash(), ?err, "invalid tx during basic validation");
                return Ok(ProcessTxResponse::InvalidTx(err));
            }
        };

        let shard_uid = shard_layout.account_id_to_shard_uid(signed_tx.transaction.signer_id());
        let shard_id = shard_uid.shard_id();

        if self.shard_tracker.cares_about_shard_this_or_next_epoch(&head.last_block_hash, shard_id)
        {
            let (state_root, constraints) = if let Some(certified_header) = &spice_certified_header
            {
                let chunk_store = self.chain_store.chunk_store();
                let root = match chunk_store.get_chunk_extra(certified_header.hash(), &shard_uid) {
                    Ok(chunk_extra) => *chunk_extra.state_root(),
                    Err(_) => {
                        if is_forwarded {
                            return Err(near_client_primitives::types::Error::Other(
                                "Node has not caught up yet".to_string(),
                            ));
                        } else {
                            self.forward_tx(&epoch_id, signed_tx)?;
                            return Ok(ProcessTxResponse::RequestRouted);
                        }
                    }
                };
                let constraints = if self.config.spice_pending_transaction_queue_enabled {
                    let ptq = self.pending_transaction_queue.lock();
                    ptq.get(&shard_uid)
                        .map(|q| q.get_pending_constraints(&signed_tx))
                        .unwrap_or_default()
                } else {
                    PendingConstraints::default()
                };
                (root, constraints)
            } else {
                let chunk_store = self.chain_store.chunk_store();
                let root = match chunk_store.get_chunk_extra(&head.last_block_hash, &shard_uid) {
                    Ok(chunk_extra) => *chunk_extra.state_root(),
                    Err(_) => {
                        if is_forwarded {
                            return Err(near_client_primitives::types::Error::Other(
                                "Node has not caught up yet".to_string(),
                            ));
                        } else {
                            self.forward_tx(&epoch_id, signed_tx)?;
                            return Ok(ProcessTxResponse::RequestRouted);
                        }
                    }
                };
                (root, PendingConstraints::default())
            };
            if let Err(err) = self.runtime.can_verify_and_charge_tx(
                &shard_layout,
                gas_price,
                state_root,
                &validated_tx,
                protocol_version,
                &constraints,
            ) {
                tracing::debug!(target: "client", ?err, "invalid tx");
                return Ok(ProcessTxResponse::InvalidTx(err));
            }
```

**File:** chain/client/src/rpc_handler.rs (L277-296)
```rust
            // Transactions only need to be recorded if this node is a chunk producer for the transaction's shard.
            if self.is_chunk_producer_for_transaction(&head, signed_tx.transaction.signer_id())? {
                let mut pool = self.tx_pool.lock();
                match pool.insert_transaction(shard_uid, validated_tx) {
                    InsertTransactionResult::Success => {
                        tracing::trace!(target: "client", ?shard_uid, tx_hash = ?signed_tx.get_hash(), "recorded a transaction");
                    }
                    InsertTransactionResult::Duplicate => {
                        tracing::trace!(target: "client", ?shard_uid, tx_hash = ?signed_tx.get_hash(), "duplicate transaction, not forwarding it");
                        return Ok(ProcessTxResponse::ValidTx);
                    }
                    InsertTransactionResult::NoSpaceLeft => {
                        if is_forwarded {
                            tracing::trace!(target: "client", ?shard_uid, tx_hash = ?signed_tx.get_hash(), "transaction pool is full, dropping the transaction");
                        } else {
                            tracing::trace!(target: "client", ?shard_uid, tx_hash = ?signed_tx.get_hash(), "transaction pool is full, trying to forward the transaction");
                        }
                    }
                }
            }
```

**File:** core/primitives/src/transaction.rs (L279-298)
```rust
impl ValidatedTransaction {
    #[allow(clippy::result_large_err)]
    pub fn new(
        config: &RuntimeConfig,
        signed_tx: SignedTransaction,
        protocol_version: ProtocolVersion,
    ) -> Result<Self, (InvalidTxError, SignedTransaction)> {
        match Self::check_valid_for_config(config, &signed_tx, protocol_version) {
            Ok(()) => {}
            Err(err) => return Err((err, signed_tx)),
        }

        if !signed_tx
            .signature
            .verify(signed_tx.get_hash().as_ref(), signed_tx.transaction.public_key())
        {
            return Err((InvalidTxError::InvalidSignature, signed_tx));
        }
        Ok(Self(signed_tx))
    }
```

**File:** chain/chain/src/runtime/mod.rs (L752-813)
```rust
    fn can_verify_and_charge_tx(
        &self,
        shard_layout: &ShardLayout,
        gas_price: Balance,
        state_root: StateRoot,
        validated_tx: &ValidatedTransaction,
        current_protocol_version: ProtocolVersion,
        pending_constraints: &PendingConstraints,
    ) -> Result<(), InvalidTxError> {
        let runtime_config = self.runtime_config_store.get_config(current_protocol_version);
        let tx = validated_tx.to_tx();
        let cost = tx_cost(runtime_config, &tx, gas_price)?;
        let shard_uid = shard_layout
            .account_id_to_shard_uid(validated_tx.to_signed_tx().transaction.signer_id());
        let trie = self.tries.get_trie_for_shard(shard_uid, state_root);
        let (signer, access_key) = get_signer_and_access_key(&trie, &validated_tx)?;
        // Here we do not know which block the transaction will be included and
        // therefore use `None` as `block_height` to skip the check on the nonce
        // upper bound.
        let block_height: Option<BlockHeight> = None;
        if let Some(nonce_index) = tx.nonce().nonce_index() {
            let current_nonce =
                get_gas_key_nonce(&trie, tx.signer_id(), tx.public_key(), nonce_index)?
                    .ok_or_else(|| {
                        let num_nonces = access_key
                            .gas_key_info()
                            .map_or(0, |gas_key_info| gas_key_info.num_nonces);
                        InvalidTxError::InvalidNonceIndex {
                            tx_nonce_index: Some(nonce_index),
                            num_nonces,
                        }
                    })?;
            match verify_and_charge_gas_key_tx_ephemeral(
                runtime_config,
                &signer,
                &access_key,
                current_nonce,
                &tx,
                &cost,
                block_height,
                pending_constraints,
            ) {
                TxVerdict::Success(_) => Ok(()),
                TxVerdict::DepositFailed { error, .. } | TxVerdict::Failed(error) => Err(error),
            }
        } else {
            match verify_and_charge_tx_ephemeral(
                runtime_config,
                &signer,
                &access_key,
                &tx,
                &cost,
                block_height,
                pending_constraints,
            ) {
                TxVerdict::Success(_) => Ok(()),
                TxVerdict::Failed(error) => Err(error),
                // verify_and_charge_tx_ephemeral never returns DepositFailed.
                TxVerdict::DepositFailed { .. } => unreachable!(),
            }
        }
    }
```

**File:** chain/pool/src/lib.rs (L87-127)
```rust
    /// Inserts a signed transaction that passed validation into the pool.
    pub fn insert_transaction(
        &mut self,
        validated_tx: ValidatedTransaction,
    ) -> InsertTransactionResult {
        let tx_hash = validated_tx.get_hash();
        if self.unique_transactions.contains(&tx_hash) {
            return InsertTransactionResult::Duplicate;
        }
        // We never expect the total size to go over `u64` during real operation as that would
        // be more than 10^9 GiB of RAM consumed for transaction pool, so panicking here is intended
        // to catch a logic error in estimation of transaction size.
        let new_total_transaction_size = self
            .total_transaction_size
            .checked_add(validated_tx.wire_size())
            .expect("Total transaction size is too large");
        if let Some(limit) = self.total_transaction_size_limit {
            if new_total_transaction_size > limit {
                return InsertTransactionResult::NoSpaceLeft;
            }
        }

        // At this point transaction is accepted to the pool.

        // This is guaranteed to succeed because of the check above that the
        // hashset does not contain this hash.  This can be improved once the
        // entries API is stabilized
        // (https://github.com/rust-lang/rust/issues/60896).
        assert_eq!(self.unique_transactions.insert(tx_hash), true);
        self.total_transaction_size = new_total_transaction_size;
        let signer_id = validated_tx.signer_id();
        let signer_public_key = validated_tx.public_key();
        self.transactions
            .entry(self.key(signer_id, signer_public_key, validated_tx.nonce().nonce_index()))
            .or_insert_with(Vec::new)
            .push(validated_tx);

        self.transaction_pool_count_metric.inc();
        self.transaction_pool_size_metric.set(self.total_transaction_size as i64);
        InsertTransactionResult::Success
    }
```

**File:** chain/jsonrpc/src/lib.rs (L3010-3039)
```rust
    // Build router
    let mut app = Router::new()
        .route("/", post(rpc_handler))
        .route("/status", get(status_handler).head(status_handler))
        .route("/health", get(health_handler).head(health_handler))
        .route("/network_info", get(network_info_handler))
        .route("/metrics", get(prometheus_handler))
        .route("/openapi.json", get(openapi_json_handler));

    if enable_debug_rpc {
        app = app
            .route("/debug/api/entity", post(handle_entity_debug))
            .route(
                "/debug/api/block_status/{starting_height}",
                #[allow(deprecated)]
                get(deprecated_debug_block_status_handler),
            )
            .route("/debug/api/block_status", get(debug_block_status_handler))
            .route("/debug/api/epoch_info/{epoch_id}", get(debug_epoch_info_handler))
            .route("/debug/api/epoch_info_light/{epoch_id}", get(debug_epoch_info_light_handler))
            .route("/debug/api/instrumented_threads", get(debug_instrumented_threads_handler))
            .route("/debug/api/{*api_path}", get(debug_handler))
            .route("/debug/client_config", get(client_config_handler))
            .route("/debug", get(debug_html))
            .route("/debug/pages/{page}", get(display_debug_html));
    }

    app.layer(get_cors(&cors_allowed_origins))
        .layer(RequestBodyLimitLayer::new(limits_config.json_payload_max_size))
        .with_state(handler)
```

**File:** chain/jsonrpc/RPC_ARCHITECTURE.md (L189-198)
```markdown
### RpcHandlerActor

Defined in `chain/client/src/rpc_handler.rs`. A **separate multithreaded actor** dedicated to transaction pre-processing. It exists to keep transaction validation work (signature checks, nonce lookups, balance verification) off the consensus-critical `ClientActor`. Thread count is configurable via `handler_threads`.

When `process_tx()` is called with a `SignedTransaction`:

1. Validates transaction validity period and basic validity (signature, etc.).
2. Determines the signer's shard via shard layout.
3. **If this node tracks the shard:** deeper validation (balance, nonce), then inserts into transaction pool or forwards to validators.
4. **If not:** forwards to a validator that tracks the shard.
```
