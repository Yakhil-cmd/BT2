Looking at the external bug's core invariant: a cancellation/rejection mechanism keyed by a hash of a cryptographic object can be bypassed if the same object has a second valid representation with a different hash.

I traced the analogous path in this codebase: the `proof_facts`/`proof` pair in `RpcInvokeTransactionV3`, the `run_proof_verification` skip-if-cached logic, and the `validate_proof_facts_and_proof_consistency` stateless check.

**Key findings from the code:**

`RpcInvokeTransactionV3` carries both `proof_facts` and `proof`. During conversion, `proof` is explicitly dropped: [1](#0-0) 

The `run_proof_verification` function skips cryptographic verification if the proof is already stored, keyed by `proof_facts.hash()`: [2](#0-1) 

The stateless validator requires `proof_facts` and `proof` to be both empty or both non-empty, but does not verify the proof's cryptographic validity at this stage: [3](#0-2) 

The transaction hash includes `proof_facts` (conditionally) but never includes `proof`: [4](#0-3) 

**Why no analog vulnerability exists:**

The external bug's exploit requires that the *same authorizing object* (the cancelled signature) can be presented in a second form that bypasses the rejection check, granting unauthorized execution. In the Sequencer:

1. The `proof` field is dropped before execution and never participates in the transaction hash, account `__validate__`, or blockifier pre-validation. It has no authorizing role in the execution path.
2. The `contains_proof` skip is keyed on `proof_facts.hash()`, not on the `proof` bytes. An attacker reusing known `proof_facts` with a garbage `proof` gains nothing — the `proof_facts` themselves (program hash, block hash, config hash) are what the blockifier validates, and those are identical to the previously-proven facts.
3. The blockifier's `validate_proof_facts` independently re-validates the semantic content of `proof_facts` (allowed program hash, block hash consistency, config hash) regardless of whether proof verification was skipped: [5](#0-4) 
4. `ProofFacts` is a `Vec<Felt>` — field elements have a canonical representation with no malleability analogous to EIP-2098 compact signatures.

The skip-if-cached behavior is an

### Citations

**File:** crates/starknet_api/src/rpc_transaction.rs (L697-713)
```rust
impl From<RpcInvokeTransactionV3> for InternalRpcInvokeTransactionV3 {
    fn from(tx: RpcInvokeTransactionV3) -> Self {
        Self {
            sender_address: tx.sender_address,
            calldata: tx.calldata,
            signature: tx.signature,
            nonce: tx.nonce,
            resource_bounds: tx.resource_bounds,
            tip: tx.tip,
            paymaster_data: tx.paymaster_data,
            account_deployment_data: tx.account_deployment_data,
            nonce_data_availability_mode: tx.nonce_data_availability_mode,
            fee_data_availability_mode: tx.fee_data_availability_mode,
            proof_facts: tx.proof_facts,
            // Note: proof field is dropped
        }
    }
```

**File:** crates/apollo_transaction_converter/src/transaction_converter.rs (L398-424)
```rust
    async fn run_proof_verification(
        proof_facts: ProofFacts,
        proof: Proof,
        proof_manager_client: SharedProofManagerClient,
    ) -> Result<bool, TransactionConverterError> {
        let contains_proof = proof_manager_client.contains_proof(proof_facts.clone()).await?;

        if contains_proof {
            return Ok(false);
        }

        let proof_facts_hash = proof_facts.hash();
        let verify_start = Instant::now();
        tokio::task::spawn_blocking(move || {
            starknet_proof_verifier::verify_proof(proof_facts, proof)
        })
        .await
        .expect("proof verification task panicked")?;
        let verify_duration = verify_start.elapsed();
        PROOF_VERIFICATION_LATENCY.record(verify_duration.as_secs_f64());
        info!(
            "Proof verification took: {verify_duration:?} for proof facts hash: \
             {proof_facts_hash:?}"
        );

        Ok(true)
    }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L249-263)
```rust
    fn validate_proof_facts_and_proof_consistency(
        &self,
        tx: &RpcInvokeTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        let RpcInvokeTransaction::V3(tx) = tx;
        let has_proof_facts = !tx.proof_facts.is_empty();
        let has_proof = !tx.proof.is_empty();
        if has_proof_facts != has_proof {
            return Err(StatelessTransactionValidatorError::ProofFactsAndProofConsistency {
                has_proof_facts,
                has_proof,
            });
        }
        Ok(())
    }
```

**File:** crates/starknet_api/src/transaction_hash.rs (L399-404)
```rust
    if !transaction.proof_facts().0.is_empty() {
        let proof_facts_hash =
            HashChain::new().chain_iter(transaction.proof_facts().0.iter()).get_poseidon_hash();
        hash_chain = hash_chain.chain(&proof_facts_hash);
    }
    Ok(TransactionHash(hash_chain.get_poseidon_hash()))
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L291-351)
```rust
    fn validate_proof_facts(
        &self,
        block_context: &BlockContext,
        state: &mut dyn State,
    ) -> TransactionPreValidationResult<()> {
        // Only Invoke V3 transactions can carry proof facts.
        let Transaction::Invoke(invoke_tx) = &self.tx else {
            return Ok(());
        };
        if invoke_tx.version() < TransactionVersion::THREE {
            return Ok(());
        }

        // Parse proof facts.
        let proof_facts = invoke_tx.proof_facts();
        let snos_proof_facts = match ProofFactsVariant::try_from(&proof_facts)
            .map_err(|e| TransactionPreValidationError::InvalidProofFacts(e.to_string()))?
        {
            ProofFactsVariant::Empty => return Ok(()),
            ProofFactsVariant::Snos(snos_proof_facts) => snos_proof_facts,
        };
        let os_constants = &block_context.versioned_constants.os_constants;

        if !os_constants.allowed_proof_versions.contains(&snos_proof_facts.proof_version.as_felt())
        {
            return Err(TransactionPreValidationError::InvalidProofFacts(format!(
                "Proof version {} is not allowed under this protocol version.",
                snos_proof_facts.proof_version
            )));
        }

        // Validate the program hash.
        let allowed = &os_constants.allowed_virtual_os_program_hashes;
        if !allowed.contains(&snos_proof_facts.program_hash) {
            return Err(TransactionPreValidationError::InvalidProofFacts(format!(
                "Virtual OS program hash {} is not allowed",
                snos_proof_facts.program_hash
            )));
        }

        // Validate the block hash and block number.
        let proof_block_hash = snos_proof_facts.block_hash.0;
        let proof_block_number = snos_proof_facts.block_number.0;
        Self::validate_proof_block_number(
            proof_block_number,
            block_context.block_info.block_number,
        )?;
        Self::validate_proof_block_hash(proof_block_hash, proof_block_number, os_constants, state)?;

        // Validate the config hash.
        let virtual_os_config_hash = block_context.virtual_os_config_hash();
        let proof_config_hash = snos_proof_facts.config_hash;
        if virtual_os_config_hash != proof_config_hash {
            return Err(TransactionPreValidationError::InvalidProofFacts(format!(
                "Virtual OS config hash mismatch. Computed virtual OS config hash: \
                 {virtual_os_config_hash}, expected virtual OS config hash: {proof_config_hash}."
            )));
        }

        Ok(())
    }
```
