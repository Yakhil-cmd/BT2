Audit Report

## Title
Missing Callback ID Validation in `push_response` for `SendTransactionResponse`, `GetSuccessorsReject`, and `SendTransactionReject` Enables Consensus Queue Injection — (`rs/replicated_state/src/bitcoin.rs`)

## Summary

The `push_response` function in `rs/replicated_state/src/bitcoin.rs` validates the `callback_id` only for the `GetSuccessorsResponse` arm, but unconditionally pushes a `ConsensusResponse` with the attacker-supplied `callback_id` for the `SendTransactionResponse`, `GetSuccessorsReject`, and `SendTransactionReject` arms. The `validate_payload` implementation in `rs/bitcoin/consensus/src/payload_builder.rs` performs no callback ID legitimacy check, only a size check. A single malicious block proposer can therefore inject a `ConsensusResponse` targeting any pending subnet call context (including `SignWithThreshold`, `SetupInitialDKG`, `ReshareChainKey`, or `CanisterHttpRequest`) into the consensus queue, causing the execution environment to consume and corrupt that context by delivering a malformed payload.

## Finding Description

**Root cause — missing guard in `push_response`:**

The `GetSuccessorsResponse` arm correctly validates the callback ID against `bitcoin_get_successors_contexts` and returns `Err(StateError::BitcoinNonMatchingResponse)` if no match is found: [1](#0-0) 

The `SendTransactionResponse` arm performs no such check and unconditionally pushes to `consensus_queue`: [2](#0-1) 

The same omission applies to `GetSuccessorsReject` and `SendTransactionReject`: [3](#0-2) 

**Root cause — payload validation does not check callback IDs:**

`validate_self_validating_payload_impl` only checks whether the payload is empty and its byte size; it never verifies that any `callback_id` in the payload corresponds to an existing Bitcoin context: [4](#0-3) 

`validate_payload` (the `BatchPayloadBuilder` implementation) delegates to the same function and adds only a size check: [5](#0-4) 

**Execution path — consensus queue is drained unconditionally:**

Every round, the scheduler drains the entire `consensus_queue` and calls `execute_subnet_message` for each entry: [6](#0-5) 

`execute_subnet_message` calls `retrieve_context`, which searches **all** context maps (SetupInitialDKG, SignWithThreshold, ReshareChainKey, CanisterHttp, BitcoinGetSuccessors, BitcoinSendTransactionInternal) and **removes** the matching entry on the first hit: [7](#0-6) 

If a context is found, the execution environment unconditionally delivers the injected payload (e.g., `EmptyBlob`) to the originating canister: [8](#0-7) 

Callback IDs are assigned from a single monotonically-increasing counter shared across all context types: [9](#0-8) 

**Delivery path — `SelfValidatingPayload` flows from block to state:**

The `SelfValidatingPayload` is part of the `BatchPayload` in a `BlockPayload::Data`. After finalization, `BatchPayload::into_messages` extracts `bitcoin_adapter_responses` directly from `self_validating.0`: [10](#0-9) 

`DemuxImpl::process_payload` calls `state.push_response_bitcoin` for each response, swallowing errors with only a debug log: [11](#0-10) 

## Impact Explanation

A single malicious subnet node acting as block proposer can craft a `BitcoinAdapterResponse { response: SendTransactionResponse, callback_id: <target> }` and embed it in the `SelfValidatingPayload` of a proposed block. All other nodes will accept the block because `validate_payload` only checks size. Upon finalization, `push_response` injects a `ConsensusResponse` with the target `callback_id` into `consensus_queue`. The scheduler delivers the `EmptyBlob` payload to the canister waiting for a threshold signature (or other subnet call). `retrieve_context` removes the context, so the legitimate response arriving later is silently dropped. The result is deterministic replicated state corruption: every honest replica executes the same block and arrives at the same corrupted state. This matches the **High** impact category: certified-state disruption and execution integrity loss affecting threshold signing, DKG, canister HTTP, and other subnet call contexts.

## Likelihood Explanation

- Requires being a subnet node with block proposer eligibility — a single Byzantine node below the consensus fault threshold suffices.
- Callback IDs are sequential integers starting from 0, observable in the certified state tree. No brute-force is needed.
- The validation gap is unconditional — no race condition or timing dependency.
- The attack is deterministic and reproducible in a state-machine test.

## Recommendation

In `push_response` (`rs/replicated_state/src/bitcoin.rs`), add the same context-existence check to the `SendTransactionResponse`, `GetSuccessorsReject`, and `SendTransactionReject` arms that already exists for `GetSuccessorsResponse`:

```rust
BitcoinAdapterResponseWrapper::SendTransactionResponse(_) => {
    let callback_id = CallbackId::from(response.callback_id);
    if !state.metadata.subnet_call_context_manager
        .bitcoin_send_transaction_internal_contexts
        .contains_key(&callback_id)
    {
        return Err(StateError::BitcoinNonMatchingResponse {
            callback_id: callback_id.get(),
        });
    }
    let payload = Payload::Data(EmptyBlob.encode());
    state.consensus_queue.push(ConsensusResponse::new(callback_id, payload));
    Ok(())
}
```

Apply the analogous guard for `GetSuccessorsReject` (check `bitcoin_get_successors_contexts`) and `SendTransactionReject` (check `bitcoin_send_transaction_internal_contexts`).

Additionally, `validate_self_validating_payload_impl` should verify that every `callback_id` in the payload corresponds to an existing Bitcoin context in the certified state, mirroring the approach used by the canister-HTTP payload builder.

## Proof of Concept

```rust
// State-machine test (no Bitcoin context registered):
let mut state = ReplicatedState::new(SUBNET_ID, SubnetType::Application);

// Register a SignWithThreshold context to obtain a known callback_id.
let target_id = state.metadata.subnet_call_context_manager.push_context(
    SubnetCallContext::SignWithThreshold(/* ... */),
);

// Craft a SendTransactionResponse with the threshold-signing callback_id.
let result = push_response(
    &mut state,
    BitcoinAdapterResponse {
        response: BitcoinAdapterResponseWrapper::SendTransactionResponse(
            SendTransactionResponse {},
        ),
        callback_id: target_id.get(), // e.g. 0
    },
);

// Currently returns Ok(()) — no error.
assert!(result.is_ok());

// The consensus queue now contains a ConsensusResponse targeting the
// SignWithThreshold context, which will be delivered as EmptyBlob.
assert_eq!(state.consensus_queue.len(), 1);
assert_eq!(state.consensus_queue[0].callback, target_id);

// When the scheduler runs, retrieve_context will remove the SignWithThreshold
// context and deliver EmptyBlob to the waiting canister.
```

### Citations

**File:** rs/replicated_state/src/bitcoin.rs (L31-39)
```rust
            let callback_id = CallbackId::from(response.callback_id);
            let context = state
                .metadata
                .subnet_call_context_manager
                .bitcoin_get_successors_contexts
                .get_mut(&callback_id)
                .ok_or_else(|| StateError::BitcoinNonMatchingResponse {
                    callback_id: callback_id.get(),
                })?;
```

**File:** rs/replicated_state/src/bitcoin.rs (L64-75)
```rust
        BitcoinAdapterResponseWrapper::SendTransactionResponse(_) => {
            // Retrieve the associated request from the call context manager.
            let callback_id = CallbackId::from(response.callback_id);
            // The response to a `send_transaction` call is always the empty blob.
            let payload = Payload::Data(EmptyBlob.encode());

            // Add response to the consensus queue.
            state
                .consensus_queue
                .push(ConsensusResponse::new(callback_id, payload));

            Ok(())
```

**File:** rs/replicated_state/src/bitcoin.rs (L77-102)
```rust
        BitcoinAdapterResponseWrapper::GetSuccessorsReject(reject) => {
            // Retrieve the associated request from the call context manager.
            let callback_id = CallbackId::from(response.callback_id);
            let reject_payload =
                Payload::Reject(RejectContext::new(reject.reject_code, reject.message));

            // Add response to the consensus queue.
            state
                .consensus_queue
                .push(ConsensusResponse::new(callback_id, reject_payload));

            Ok(())
        }
        BitcoinAdapterResponseWrapper::SendTransactionReject(reject) => {
            // Retrieve the associated request from the call context manager.
            let callback_id = CallbackId::from(response.callback_id);
            let reject_payload =
                Payload::Reject(RejectContext::new(reject.reject_code, reject.message));

            // Add response to the consensus queue.
            state
                .consensus_queue
                .push(ConsensusResponse::new(callback_id, reject_payload));

            Ok(())
        }
```

**File:** rs/bitcoin/consensus/src/payload_builder.rs (L234-251)
```rust
    fn validate_self_validating_payload_impl(
        &self,
        payload: &SelfValidatingPayload,
        validation_context: &ValidationContext,
    ) -> Result<NumBytes, SelfValidatingPayloadValidationError> {
        let since = Instant::now();

        // An empty block is always valid.
        if *payload == SelfValidatingPayload::default() {
            return Ok(0.into());
        }

        self.metrics
            .observe_validate_duration(VALIDATION_STATUS_VALID, since);
        let size = NumBytes::new(payload.count_bytes() as u64);

        Ok(size)
    }
```

**File:** rs/bitcoin/consensus/src/payload_builder.rs (L357-397)
```rust
    fn validate_payload(
        &self,
        height: Height,
        proposal_context: &ProposalContext,
        payload: &[u8],
        past_payloads: &[PastPayload],
    ) -> Result<(), PayloadValidationError> {
        if payload.is_empty() {
            return Ok(());
        }
        let raw_payload_len = payload.len();

        let delivered_ids = parse::parse_past_payload_ids(past_payloads, &self.log);
        let payload = parse::bytes_to_payload(payload).map_err(|e| {
            ValidationError::InvalidArtifact(
                consensus::InvalidPayloadReason::InvalidSelfValidatingPayload(
                    InvalidSelfValidatingPayloadReason::DecodeError(e),
                ),
            )
        })?;
        let num_responses = payload.len();

        let _ = self.validate_self_validating_payload_impl(
            &SelfValidatingPayload::new(payload),
            proposal_context.validation_context,
        )?;

        if raw_payload_len as u64 > MAX_BITCOIN_PAYLOAD_IN_BYTES {
            if num_responses == 1 {
                warn!(self.log, "Bitcoin Payload oversized");
            } else {
                return Err(ValidationError::InvalidArtifact(
                    consensus::InvalidPayloadReason::InvalidSelfValidatingPayload(
                        InvalidSelfValidatingPayloadReason::PayloadTooBig,
                    ),
                ));
            }
        }

        Ok(())
    }
```

**File:** rs/execution_environment/src/scheduler.rs (L1299-1325)
```rust
            while let Some(response) = state.consensus_queue.pop() {
                let (new_state, _) = self.execute_subnet_message(
                    // Wrap the callback ID and payload into a Response, to make it easier for
                    // `execute_subnet_message()` to deal with. All other fields will be ignored by
                    // `execute_subnet_message()`.
                    SubnetMessage::Response(
                        Response {
                            originator: CanisterId::ic_00(),
                            respondent: CanisterId::ic_00(),
                            originator_reply_callback: response.callback,
                            refund: Cycles::zero(),
                            response_payload: response.payload,
                            deadline: NO_DEADLINE,
                        }
                        .into(),
                    ),
                    state,
                    &mut csprng,
                    current_round,
                    &mut subnet_round_limits,
                    registry_settings,
                    replica_version,
                    &measurement_scope,
                    &chain_key_data,
                );
                state = new_state;
            }
```

**File:** rs/replicated_state/src/metadata_state/subnet_call_context_manager.rs (L237-267)
```rust
    pub fn push_context(&mut self, context: SubnetCallContext) -> CallbackId {
        let callback_id = CallbackId::new(self.next_callback_id);
        self.next_callback_id += 1;

        match context {
            SubnetCallContext::SetupInitialDKG(context) => {
                self.setup_initial_dkg_contexts.insert(callback_id, context);
            }
            SubnetCallContext::SignWithThreshold(context) => {
                self.sign_with_threshold_contexts
                    .insert(callback_id, context);
            }
            SubnetCallContext::CanisterHttpRequest(context) => {
                self.canister_http_request_contexts
                    .insert(callback_id, context);
            }
            SubnetCallContext::ReshareChainKey(context) => {
                self.reshare_chain_key_contexts.insert(callback_id, context);
            }
            SubnetCallContext::BitcoinGetSuccessors(context) => {
                self.bitcoin_get_successors_contexts
                    .insert(callback_id, context);
            }
            SubnetCallContext::BitcoinSendTransactionInternal(context) => {
                self.bitcoin_send_transaction_internal_contexts
                    .insert(callback_id, context);
            }
        };

        callback_id
    }
```

**File:** rs/replicated_state/src/metadata_state/subnet_call_context_manager.rs (L269-350)
```rust
    pub fn retrieve_context(
        &mut self,
        callback_id: CallbackId,
        logger: &ReplicaLogger,
    ) -> Option<SubnetCallContext> {
        self.setup_initial_dkg_contexts
            .remove(&callback_id)
            .map(|context| {
                info!(
                    logger,
                    "Received the response for SetupInitialDKG request for target {:?}",
                    context.target_id
                );
                SubnetCallContext::SetupInitialDKG(context)
            })
            .or_else(|| {
                self.sign_with_threshold_contexts
                    .remove(&callback_id)
                    .map(|context| {
                        info!(
                            logger,
                            "Received the response for SignWithThreshold request with id {:?} from {:?}",
                            callback_id,
                            context.request.sender
                        );
                        SubnetCallContext::SignWithThreshold(context)
                    })
            })
            .or_else(|| {
                self.reshare_chain_key_contexts
                    .remove(&callback_id)
                    .map(|context| {
                        info!(
                            logger,
                            "Received the response for ReshareChainKey request with key_id {:?} and callback id {:?} from {:?}",
                            context.key_id,
                            context.request.sender_reply_callback,
                            context.request.sender
                        );
                        SubnetCallContext::ReshareChainKey(context)
                    })
            })
            .or_else(|| {
                self.canister_http_request_contexts
                    .remove(&callback_id)
                    .map(|context| {
                        info!(
                            logger,
                            "Received the response for HttpRequest with callback id {:?} from {:?}",
                            context.request.sender_reply_callback,
                            context.request.sender
                        );
                        SubnetCallContext::CanisterHttpRequest(context)
                    })
            })
            .or_else(|| {
                self.bitcoin_get_successors_contexts
                    .remove(&callback_id)
                    .map(|context| {
                        info!(
                            logger,
                            "Received the response for BitcoinGetSuccessors with callback id {:?} from {:?}",
                            context.request.sender_reply_callback,
                            context.request.sender
                        );
                        SubnetCallContext::BitcoinGetSuccessors(context)
                    })
            })
            .or_else(|| {
                self.bitcoin_send_transaction_internal_contexts
                    .remove(&callback_id)
                    .map(|context| {
                        info!(
                            logger,
                            "Received the response for BitcoinSendTransactionInternal with callback id {:?} from {:?}",
                            context.request.sender_reply_callback,
                            context.request.sender
                        );
                        SubnetCallContext::BitcoinSendTransactionInternal(context)
                    })
            })
    }
```

**File:** rs/execution_environment/src/execution_environment.rs (L698-785)
```rust
            SubnetMessage::Response(response) => {
                let context = state
                    .metadata
                    .subnet_call_context_manager
                    .retrieve_context(response.originator_reply_callback, &self.log);
                return match context {
                    None => (state, ExecuteSubnetMessageResultType::Finished),
                    Some(context) => {
                        let time_elapsed =
                            state.time().saturating_duration_since(context.get_time());
                        let request = context.get_request();

                        if let SubnetCallContext::CanisterHttpRequest(context) = &context {
                            let old_price = self.cycles_account_manager.http_request_fee(
                                context.variable_parts_size(),
                                context.max_response_bytes,
                                state.get_own_subnet_cycles_config(),
                            );

                            let new_price = self.cycles_account_manager.http_request_fee_beta(
                                context.variable_parts_size(),
                                context.max_response_bytes,
                                state.get_own_subnet_cycles_config(),
                                NumBytes::from(response.payload_size_bytes()),
                            );

                            self.metrics.observe_http_outcall_price_change(
                                old_price.nominal(),
                                new_price.nominal(),
                            );
                            self.metrics
                                .observe_http_outcall_request(context, &response);

                            let max_response_size = match context.max_response_bytes {
                                Some(response_size) => response_size.get(),
                                // Defaults to maximum response size.
                                None => MAX_CANISTER_HTTP_RESPONSE_BYTES,
                            };

                            info!(
                                self.log,
                                "Canister Http request with payload_size {}, max_response_size {}, subnet_size {}, reply_callback_id {}, sender {}, process_id {}",
                                response.payload_size_bytes().get(),
                                max_response_size,
                                registry_settings.subnet_size,
                                context.request.sender_reply_callback,
                                context.request.sender,
                                std::process::id(),
                            );
                        }

                        self.metrics.observe_subnet_message(
                            &request.method_name,
                            time_elapsed.as_secs_f64(),
                            &match &response.response_payload {
                                Payload::Data(_) => Ok(()),
                                Payload::Reject(_) => Err(ErrorCode::CanisterRejectedMessage),
                            },
                        );

                        if let (
                            SubnetCallContext::SignWithThreshold(threshold_context),
                            Payload::Data(_),
                        ) = (&context, &response.response_payload)
                        {
                            *state
                                .metadata
                                .subnet_metrics
                                .threshold_signature_agreements
                                .entry(threshold_context.key_id())
                                .or_default() += 1;
                        }

                        state.push_subnet_output_response(
                            Response {
                                originator: request.sender,
                                respondent: CanisterId::from(self.own_subnet_id),
                                originator_reply_callback: request.sender_reply_callback,
                                refund: request.payment,
                                response_payload: response.response_payload.clone(),
                                deadline: request.deadline,
                            }
                            .into(),
                        );

                        (state, ExecuteSubnetMessageResultType::Finished)
                    }
                };
```

**File:** rs/types/types/src/batch.rs (L213-224)
```rust
    pub fn into_messages(self) -> Result<BatchMessages, IntoMessagesError> {
        Ok(BatchMessages {
            signed_ingress_msgs: self
                .ingress
                .try_into()
                .map_err(IntoMessagesError::IngressPayloadError)?,
            certified_stream_slices: self.xnet.stream_slices,
            bitcoin_adapter_responses: self.self_validating.0,
            query_stats: QueryStatsPayload::deserialize(&self.query_stats)
                .map_err(IntoMessagesError::QueryStatsPayloadError)?,
        })
    }
```

**File:** rs/messaging/src/routing/demux.rs (L86-94)
```rust
        for response in batch_messages.bitcoin_adapter_responses.into_iter() {
            state.push_response_bitcoin(response).unwrap_or_else(|err| {
                debug!(
                    self.log,
                    "Error pushing the response from bitcoin adapter {}",
                    err.to_string()
                )
            });
        }
```
