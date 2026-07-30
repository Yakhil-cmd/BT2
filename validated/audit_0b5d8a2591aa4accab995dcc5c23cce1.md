[1](#0-0) [2](#0-1) [3](#0-2) [4](#0-3)

### Citations

**File:** crates/sui-core/src/safe_client.rs (L184-223)
```rust
    fn check_signed_effects_plain(
        &self,
        digest: &TransactionDigest,
        signed_effects: SignedTransactionEffects,
        expected_effects_digest: Option<&TransactionEffectsDigest>,
    ) -> SuiResult<SignedTransactionEffects> {
        // Check it has the right signer
        fp_ensure!(
            signed_effects.auth_sig().authority == self.address,
            SuiErrorKind::ByzantineAuthoritySuspicion {
                authority: self.address,
                reason: format!(
                    "Unexpected validator address in the signed effects signature: {:?}",
                    signed_effects.auth_sig().authority
                ),
            }
            .into()
        );
        // Checks it concerns the right tx
        fp_ensure!(
            signed_effects.data().transaction_digest() == digest,
            SuiErrorKind::ByzantineAuthoritySuspicion {
                authority: self.address,
                reason: "Unexpected tx digest in the signed effects".to_string()
            }
            .into()
        );
        // check that the effects digest is correct.
        if let Some(effects_digest) = expected_effects_digest {
            fp_ensure!(
                signed_effects.digest() == effects_digest,
                SuiErrorKind::ByzantineAuthoritySuspicion {
                    authority: self.address,
                    reason: "Effects digest does not match with expected digest".to_string()
                }
                .into()
            );
        }
        self.get_committee(&signed_effects.epoch())?;
        Ok(signed_effects)
```

**File:** crates/sui-core/src/safe_client.rs (L226-258)
```rust
    fn check_transaction_info(
        &self,
        digest: &TransactionDigest,
        transaction: Transaction,
        status: TransactionStatus,
    ) -> SuiResult<PlainTransactionInfoResponse> {
        fp_ensure!(
            digest == transaction.digest(),
            SuiErrorKind::ByzantineAuthoritySuspicion {
                authority: self.address,
                reason: "Signed transaction digest does not match with expected digest".to_string()
            }
            .into()
        );
        match status {
            TransactionStatus::Signed(signed) => {
                self.get_committee(&signed.epoch)?;
                Ok(PlainTransactionInfoResponse::Signed(
                    SignedTransaction::new_from_data_and_sig(transaction.into_data(), signed),
                ))
            }
            TransactionStatus::Executed(_cert_opt, effects, events) => {
                // `cert_opt` is permanently None: validators no longer aggregate or persist
                // per-transaction quorum signatures.
                let signed_effects = self.check_signed_effects_plain(digest, effects, None)?;
                Ok(PlainTransactionInfoResponse::Executed(
                    transaction,
                    signed_effects,
                    events,
                ))
            }
        }
    }
```

**File:** crates/sui-core/src/safe_client.rs (L304-330)
```rust
    /// Wait for effects of a transaction that has been submitted to the network
    /// through the `submit_transaction` API.
    pub async fn wait_for_effects(
        &self,
        request: WaitForEffectsRequest,
        client_addr: Option<SocketAddr>,
    ) -> Result<WaitForEffectsResponse, SuiError> {
        let _timer = self.metrics.handle_certificate_latency.start_timer();
        let wait_for_effects_resp = self
            .authority_client
            .wait_for_effects(request, client_addr)
            .await?;

        match &wait_for_effects_resp {
            WaitForEffectsResponse::Executed {
                effects_digest: _,
                details: Some(details),
            } => {
                self.verify_executed_data((**details).clone())?;
            }
            _ => {
                // No additional verification needed for other response types
            }
        };

        Ok(wait_for_effects_resp)
    }
```

**File:** crates/sui-core/src/authority_client.rs (L1-1)
```rust
// Copyright (c) 2021, Facebook, Inc. and its affiliates
```
