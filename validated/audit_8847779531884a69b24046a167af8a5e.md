No vulnerability found for this question.

Nearcore implements a well-enforced analog to the Solidity `deadline`/`ensure` check: transaction "expiration" is validated via `check_transaction_validity_period` in `chain/chain/src/store/utils.rs` and `chain/chain/src/store/mod.rs`, which compares `prev_block_header.height()` against the transaction's `block_hash` height plus `transaction_validity_period`, rejecting the tx with `InvalidTxError::Expired` if the check fails. [1](#0-0) 
This check is actively enforced in the RPC transaction-submission path. [2](#0-1) 
It is also enforced again during chunk application/prepare-transactions and applying transactions, with a per-transaction expiration flag that is checked before running full validation. [3](#0-2) [4](#0-3) 
and once more when transactions are pulled from the pool for inclusion into a chunk (`chain_validate`). [5](#0-4) 

The only place this check can be bypassed is behind the `test_features` cfg flag used for adversarial/malicious-producer test scenarios (`AdvProduceChunksMode::ProduceWithoutTxValidityCheck`), which is explicitly test-only tooling, not reachable in production by an unprivileged account, and is excluded per the validation rules (mocked-only paths). [6](#0-5) [7](#0-6) 

There is also explicit test coverage confirming expired transactions are rejected end-to-end via RPC. [8](#0-7) 

No reachable, unprivileged production code path was found where the deadline/expiration analog is disabled or ineffective, so this report's bug class does not have a valid analog in nearcore.

### Citations

**File:** chain/chain/src/store/utils.rs (L56-75)
```rust
pub fn check_transaction_validity_period(
    chain_store: &ChainStoreAdapter,
    prev_block_header: &BlockHeader,
    base_block_hash: &CryptoHash,
    transaction_validity_period: BlockHeightDelta,
) -> Result<(), InvalidTxError> {
    let base_header =
        chain_store.get_block_header(base_block_hash).map_err(|_| InvalidTxError::Expired)?;

    metrics::CHAIN_VALIDITY_PERIOD_CHECK_DELAY
        .observe(prev_block_header.height().saturating_sub(base_header.height()) as f64);

    // First check the distance between blocks
    if prev_block_header.height() > base_header.height() + transaction_validity_period {
        return Err(InvalidTxError::Expired);
    }

    // Then check if there is a path between the blocks (`base` is an ancestor of `prev`)
    validity_period_validate_is_ancestor(&base_header, prev_block_header, chain_store)
}
```

**File:** chain/client/src/rpc_handler.rs (L165-173)
```rust
        if let Err(e) = check_transaction_validity_period(
            &self.chain_store,
            &cur_block_header,
            signed_tx.transaction.block_hash(),
            self.config.transaction_validity_period,
        ) {
            tracing::debug!(target: "client", ?signed_tx, "invalid tx: expired or from a different fork");
            return Ok(ProcessTxResponse::InvalidTx(e));
        }
```

**File:** runtime/runtime/src/types.rs (L22-26)
```rust
impl SignedValidPeriodTransactions {
    pub fn new(transactions: Vec<SignedTransaction>, validity_check_results: Vec<bool>) -> Self {
        assert_eq!(transactions.len(), validity_check_results.len());
        Self { transactions, transaction_validity_check_passed: validity_check_results }
    }
```

**File:** runtime/runtime/src/lib.rs (L1866-1889)
```rust
                let (maybe_expired_txs, tx_expiration_flags) =
                    signed_txs.get_potentially_expired_transactions_and_expiration_flags();
                maybe_expired_txs
                    .par_iter()
                    .zip(tx_expiration_flags.par_iter())
                    .zip(validations.par_iter_mut())
                    .for_each(|((tx, non_expired), validation)| {
                        if !non_expired {
                            *validation = Some(InvalidTxError::Expired);
                            return;
                        }
                        let tx_hash = tx.hash();
                        let v = validate_transaction(
                            &processing_state.apply_state.config,
                            tx.clone(),
                            protocol_version,
                        )
                        .map_err(|(err, _)| err)
                        .map(|_| ());
                        if let Err(err) = v {
                            tracing::debug!(?tx_hash, error=?&err, "transaction invalid");
                            *validation = Some(err);
                        }
                    });
```

**File:** chain/chain/src/runtime/mod.rs (L1044-1049)
```rust
                // Verifying the transaction is on the same chain and hasn't expired yet.
                if !chain_validate(&validated_tx.to_signed_tx()) {
                    tracing::trace!(target: "runtime", tx=?validated_tx.get_hash(), "discarding transaction that failed chain validation");
                    rejected_invalid_for_chain += 1;
                    continue;
                }
```

**File:** chain/client/src/chunk_producer.rs (L698-713)
```rust
        #[cfg(feature = "test_features")]
        if matches!(
            self.adversarial.produce_mode,
            Some(AdvProduceChunksMode::ProduceWithoutTx)
                | Some(AdvProduceChunksMode::ProduceWithoutTxVerification)
        ) {
            return;
        }

        #[cfg(feature = "test_features")]
        let tx_validity_period_check: Box<
            dyn Fn(&SignedTransaction) -> bool + Send + 'static,
        > = match self.adversarial.produce_mode {
            Some(AdvProduceChunksMode::ProduceWithoutTxValidityCheck) => Box::new(|_| true),
            _ => Box::new(tx_validity_period_check),
        };
```

**File:** test-loop-tests/src/tests/malicious_chunk_producer.rs (L102-114)
```rust
    // Produce chunks without validity checks! The chunks should contain the transactions, but the
    // validators should simply discard the transactions.
    // For a good measure insert some invalid transactions that may be invalid in other ways than
    // them having been expired.
    let data_clone = node_datas.clone();
    test_loop.send_adhoc_event("produce chunks without validity checks".into(), move |_| {
        data_clone[0]
            .client_sender
            .send(NetworkAdversarialMessage::AdvInsertInvalidTransactions(true));
        data_clone[0].client_sender.send(NetworkAdversarialMessage::AdvProduceChunks(
            AdvProduceChunksMode::ProduceWithoutTxValidityCheck,
        ));
    });
```

**File:** chain/jsonrpc/jsonrpc-tests/tests/rpc_transactions.rs (L100-153)
```rust
/// Test that expired transaction should be rejected
#[tokio::test]
async fn test_expired_tx() {
    // Create setup with very short transaction validity period (1 block)
    let accounts = vec!["test1".parse().unwrap(), "test2".parse().unwrap()];
    let setup = create_test_setup_with_accounts_and_validity(
        accounts,
        "test1".parse().unwrap(),
        "test1".parse().unwrap(),
        1, // Very short validity period
    );
    let client = new_client(&setup.server_addr);

    // Get initial block info
    let initial_block = client.block(BlockReference::latest()).await.unwrap();
    let old_block_hash = initial_block.header.hash;

    // Wait for at least 2 more blocks to be produced so transaction becomes expired
    wait_or_timeout(100, 10000, || async {
        let current_block = client.block(BlockReference::latest()).await.unwrap();
        if current_block.header.height >= initial_block.header.height + 2 {
            ControlFlow::Break(())
        } else {
            ControlFlow::Continue(())
        }
    })
    .await
    .expect("Should produce at least 2 more blocks");

    // Try to send transaction with the old block hash (should be expired)
    let signer = InMemorySigner::test_signer(&"test1".parse().unwrap());
    let tx = SignedTransaction::send_money(
        1,
        "test1".parse().unwrap(),
        "test2".parse().unwrap(),
        &signer,
        Balance::from_yoctonear(100),
        old_block_hash,
    );
    let bytes = borsh::to_vec(&tx).unwrap();

    // This should fail with "Expired" error
    match client.broadcast_tx_commit(to_base64(&bytes)).await {
        Err(err) => {
            assert_eq!(
                *err.data.unwrap(),
                serde_json::json!({"TxExecutionError": {
                    "InvalidTxError": "Expired"
                }})
            );
        }
        Ok(_) => panic!("Expected transaction to be rejected as expired"),
    }
}
```
