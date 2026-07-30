[1](#0-0) [2](#0-1)

### Citations

**File:** crates/sui-core/src/transaction_orchestrator.rs (L524-562)
```rust
        // Add transaction to WAL log.
        let guard =
            TransactionSubmissionGuard::new(self.pending_tx_log.clone(), &verified_transaction);
        let is_new_transaction = guard.is_new_transaction();

        let include_events = request.include_events;
        let include_input_objects = request.include_input_objects;
        let include_output_objects = request.include_output_objects;
        let include_auxiliary_data = request.include_auxiliary_data;

        // Check if transaction has already been executed locally and return cached results
        if let Some(effects) = self
            .validator_state
            .get_transaction_cache_reader()
            .get_executed_effects(&tx_digest)
        {
            self.metrics.early_cached_response.inc();
            debug!(
                ?tx_digest,
                "Returning cached results for already-executed transaction"
            );
            let response = self.build_response_from_local_effects(
                effects,
                include_events,
                include_input_objects,
                include_output_objects,
            )?;
            return Ok((response, true));
        }

        let finality_timeout = std::env::var("WAIT_FOR_FINALITY_TIMEOUT_SECS")
            .ok()
            .and_then(|v| v.parse().ok())
            .map(Duration::from_secs)
            .unwrap_or(WAIT_FOR_FINALITY_TIMEOUT);

        let num_submissions = if !is_new_transaction {
            // No need to submit when the transaction is already being processed.
            0
```

**File:** crates/sui-core/src/transaction_orchestrator.rs (L613-653)
```rust
        let mut last_execution_error: Option<TransactionSubmissionError> = None;

        // Wait for execution result outside of this call to become available.
        let digests = [tx_digest];
        let mut local_effects_future = self
            .validator_state
            .get_transaction_cache_reader()
            .notify_read_executed_effects_may_fail(
                "TransactionOrchestrator::notify_read_execute_transaction_with_effects_waiting",
                &digests,
            )
            .boxed();

        // Wait for execution timeout.
        let mut timeout_future = tokio::time::sleep(finality_timeout).boxed();

        loop {
            tokio::select! {
                // Local effects might be available
                all_effects_result = &mut local_effects_future => {
                    let all_effects = all_effects_result
                        .map_err(TransactionSubmissionError::TransactionDriverInternalError)?;
                    if all_effects.len() != 1 {
                        break Err(TransactionSubmissionError::TransactionDriverInternalError(
                            SuiErrorKind::Unknown(format!("Unexpected number of effects found: {}", all_effects.len())).into()
                        ));
                    }
                    debug!(
                        "Effects became available while execution was running"
                    );
                    self.metrics.concurrent_execution.inc();

                    let effects = all_effects.into_iter().next().unwrap();
                    let response = self.build_response_from_local_effects(
                        effects,
                        include_events,
                        include_input_objects,
                        include_output_objects,
                    )?;
                    break Ok((response, true));
                }
```
