### Title
Consensus Proposal Path Bypasses OS-Enforced Stateless Validations, Allowing Finalized-but-Unprovable Blocks — (`crates/apollo_consensus_orchestrator/src/validate_proposal.rs`)

### Summary

The gateway's `StatelessTransactionValidator` explicitly enforces several constraints that the Starknet OS requires (empty `paymaster_data`, empty `account_deployment_data`, `nonce_data_availability_mode = L1`, `fee_data_availability_mode = L1`). These checks exist solely to prevent transactions from failing the OS. However, transactions arriving via the consensus proposal path (`handle_proposal_part` → `convert_consensus_tx_to_internal_consensus_tx`) bypass all of these validations. A malicious proposer can include OS-invalid transactions in a proposal; validator nodes accept and execute them, producing a finalized block that the OS cannot prove.

### Finding Description

**Gateway path (protected):**

`StatelessTransactionValidator::validate()` enforces, among others:

```rust
Self::validate_empty_account_deployment_data(tx)?;  // "OS enforces empty"
Self::validate_empty_paymaster_data(tx)?;            // "OS enforces empty"
self.validate_nonce_data_availability_mode(tx)?;     // "OS enforces L1"
self.validate_fee_data_availability_mode(tx)?;       // "OS enforces L1"
```

The comments are explicit: [1](#0-0) [2](#0-1) 

Every transaction submitted via RPC or P2P gossip passes through this validator before reaching the mempool. [3](#0-2) 

**Consensus path (unprotected):**

When a validator node receives a proposal from a proposer, `handle_proposal_part` converts each transaction batch via `convert_consensus_tx_to_internal_consensus_tx`: [4](#0-3) 

This calls `convert_rpc_tx_to_internal`, which performs only a `compiled_class_hash` check for Declare transactions and a contract address derivation for DeployAccount. It applies **none** of the OS-enforced stateless checks: [5](#0-4) 

The converted transactions are forwarded directly to the batcher via `send_txs_for_proposal` with no intervening stateless validation. [6](#0-5) 

**Execution outcome:**

The blockifier does not enforce `paymaster_data` emptiness or DA mode constraints — those are OS-level invariants. The blockifier executes the transaction normally, both the proposer's and validator's batchers produce the same block commitment, the proposal is accepted, and the block is finalized. When the block is later submitted to the Starknet OS for proof generation, the OS fails because the transaction violates its invariants, making the block unprovable.

### Impact Explanation

A finalized block that cannot be proven breaks the L2→L1 state commitment chain. The OS-enforced constraints on `paymaster_data`, `account_deployment_data`, and DA modes are not optional gateway filters — they are hard requirements of the Cairo proving program. A block containing a transaction with `paymaster_data = [0x1]` or `nonce_data_availability_mode = L2` will cause the OS to abort proof generation for that block. This maps to: **Critical — Wrong state/receipt/revert result from blockifier/syscall/execution logic for accepted input**, and **Critical — Invalid transaction accepted through paymaster or account-deployment logic**.

### Likelihood Explanation

Any validator that acts as proposer can craft a `ConsensusTransaction::RpcTransaction` with OS-invalid fields and include it in a proposal. Validator nodes will accept the proposal because `handle_proposal_part` performs no stateless validation. The proposer's own batcher will also execute the transaction (ignoring the invalid fields at the blockifier level), so both sides compute the same commitment and the proposal passes consensus. The attack requires control of one proposer slot, which is achievable by any participant in the validator set.

### Recommendation

Apply the same OS-enforced stateless checks to transactions received via the consensus path. The cleanest fix is to call `StatelessTransactionValidator::validate()` (or an equivalent subset covering the OS-enforced invariants) inside `handle_proposal_part` before forwarding transactions to the batcher, analogous to how the gateway calls it before conversion:

```rust
// In handle_proposal_part, after deserializing each ConsensusTransaction:
for tx in &txs {
    if let ConsensusTransaction::RpcTransaction(rpc_tx) = tx {
        stateless_validator.validate(rpc_tx)?;
    }
}
```

At minimum, the four OS-enforced checks (`validate_empty_paymaster_data`, `validate_empty_account_deployment_data`, `validate_nonce_data_availability_mode`, `validate_fee_data_availability_mode`) must be applied on the consensus path.

### Proof of Concept

1. Construct an `RpcInvokeTransactionV3` with `paymaster_data: PaymasterData(vec![Felt::ONE])` (non-empty, violating the OS invariant).
2. Wrap it as `ConsensusTransaction::RpcTransaction(...)` and include it in a `ProposalPart::Transactions` batch sent from a proposer node.
3. The validator's `handle_proposal_part` calls `convert_consensus_tx_to_internal_consensus_tx`, which calls `convert_rpc_tx_to_internal`. Observe that `validate_empty_paymaster_data` is never called — the transaction is accepted and forwarded to the batcher. [7](#0-6) 
4. The batcher executes the transaction (blockifier ignores `paymaster_data`), both sides compute the same commitment, and the proposal is finalized.
5. When the OS attempts to prove the block, it encounters the non-empty `paymaster_data` and aborts, leaving the block unprovable.

The same attack applies with `account_deployment_data: AccountDeploymentData(vec![Felt::ONE])`, `nonce_data_availability_mode: DataAvailabilityMode::L2`, or `fee_data_availability_mode: DataAvailabilityMode::L2`. [8](#0-7)

### Citations

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L100-118)
```rust
    /// The Starknet OS enforces that the deployer data is empty. We add this validation here in the
    /// gateway to prevent transactions from failing the OS.
    fn validate_empty_account_deployment_data(
        tx: &RpcTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        let account_deployment_data = match tx {
            RpcTransaction::DeployAccount(_) => return Ok(()),
            RpcTransaction::Declare(RpcDeclareTransaction::V3(tx)) => &tx.account_deployment_data,
            RpcTransaction::Invoke(RpcInvokeTransaction::V3(tx)) => &tx.account_deployment_data,
        };

        if account_deployment_data.is_empty() {
            Ok(())
        } else {
            Err(StatelessTransactionValidatorError::NonEmptyField {
                field_name: "account_deployment_data".to_string(),
            })
        }
    }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L120-140)
```rust
    /// The Starknet OS enforces that the paymaster data is empty. We add this validation here in
    /// the gateway to prevent transactions from failing the OS.
    fn validate_empty_paymaster_data(
        tx: &RpcTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        let paymaster_data = match tx {
            RpcTransaction::DeployAccount(RpcDeployAccountTransaction::V3(tx)) => {
                &tx.paymaster_data
            }
            RpcTransaction::Declare(RpcDeclareTransaction::V3(tx)) => &tx.paymaster_data,
            RpcTransaction::Invoke(RpcInvokeTransaction::V3(tx)) => &tx.paymaster_data,
        };

        if paymaster_data.is_empty() {
            Ok(())
        } else {
            Err(StatelessTransactionValidatorError::NonEmptyField {
                field_name: "paymaster_data".to_string(),
            })
        }
    }
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L197-229)
```rust
    /// The Starknet OS enforces that the nonce data availability mode is L1. We add this validation
    /// here in the gateway to prevent transactions from failing the OS.
    fn validate_nonce_data_availability_mode(
        &self,
        tx: &RpcTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        let expected_da_mode = DataAvailabilityMode::L1;
        let da_mode = *tx.nonce_data_availability_mode();
        if da_mode != expected_da_mode {
            return Err(StatelessTransactionValidatorError::InvalidDataAvailabilityMode {
                field_name: "nonce".to_string(),
            });
        };

        Ok(())
    }

    /// The Starknet OS enforces that the fee data availability mode is L1. We add this validation
    /// here in the gateway to prevent transactions from failing the OS.
    fn validate_fee_data_availability_mode(
        &self,
        tx: &RpcTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
        let expected_fee_mode = DataAvailabilityMode::L1;
        let fee_mode = *tx.fee_data_availability_mode();
        if fee_mode != expected_fee_mode {
            return Err(StatelessTransactionValidatorError::InvalidDataAvailabilityMode {
                field_name: "fee".to_string(),
            });
        };

        Ok(())
    }
```

**File:** crates/apollo_gateway/src/gateway.rs (L235-237)
```rust
        // Perform stateless validations.
        self.stateless_tx_validator.validate(&tx)?;

```

**File:** crates/apollo_consensus_orchestrator/src/validate_proposal.rs (L598-617)
```rust
        Some(ProposalPart::Transactions(TransactionBatch { transactions: txs })) => {
            // TODO(guyn): check that the length of txs and the number of batches we receive is not
            // so big it would fill up the memory (in case of a malicious proposal)
            debug!("Received transaction batch with {} txs", txs.len());
            let conversion_results =
                futures::future::join_all(txs.into_iter().map(|tx| {
                    transaction_converter.convert_consensus_tx_to_internal_consensus_tx(tx)
                }))
                .await
                .into_iter()
                .collect::<Result<Vec<_>, _>>();
            let conversion_results = match conversion_results {
                Ok(results) => results,
                Err(e) => {
                    return HandledProposalPart::Failed(format!(
                        "Failed to convert transactions. Stopping the build of the current \
                         proposal. {e:?}"
                    ));
                }
            };
```

**File:** crates/apollo_consensus_orchestrator/src/validate_proposal.rs (L633-646)
```rust
            content.push(txs.clone());
            let input = SendTxsForProposalInput { proposal_id, txs };
            let response = match batcher.send_txs_for_proposal(input).await {
                Ok(response) => response,
                Err(e) => {
                    return HandledProposalPart::Failed(format!(
                        "Failed to send transactions to batcher: {e:?}"
                    ));
                }
            };
            match response {
                SendTxsForProposalStatus::Processing => HandledProposalPart::Continue,
                SendTxsForProposalStatus::InvalidProposal(err) => HandledProposalPart::Invalid(err),
            }
```

**File:** crates/apollo_transaction_converter/src/transaction_converter.rs (L334-393)
```rust
    async fn convert_rpc_tx_to_internal(
        &self,
        tx: RpcTransaction,
    ) -> TransactionConverterResult<(InternalRpcTransaction, Option<(ProofFacts, Proof)>)> {
        let (tx_without_hash, proof_data) = match tx {
            RpcTransaction::Invoke(RpcInvokeTransaction::V3(tx)) => {
                let proof_data = if tx.proof_facts.is_empty() {
                    None
                } else {
                    Some((tx.proof_facts.clone(), tx.proof.clone()))
                };
                (InternalRpcTransactionWithoutTxHash::Invoke(tx.into()), proof_data)
            }
            RpcTransaction::Declare(RpcDeclareTransaction::V3(tx)) => {
                let ClassHashes { class_hash, executable_class_hash_v2 } =
                // TODO(Dori): Make this async and spawn a task to compile and add it to the class manager.
                    self.class_manager_client.add_class(tx.contract_class).await?;
                // TODO(Aviv): Ensure that we do not want to
                // allow declare with compiled class hash v1.
                if tx.compiled_class_hash != executable_class_hash_v2 {
                    return Err(TransactionConverterError::ValidateCompiledClassHashError(
                        ValidateCompiledClassHashError::CompiledClassHashMismatch {
                            computed_class_hash: executable_class_hash_v2,
                            supplied_class_hash: tx.compiled_class_hash,
                        },
                    ));
                }
                (
                    InternalRpcTransactionWithoutTxHash::Declare(InternalRpcDeclareTransactionV3 {
                        sender_address: tx.sender_address,
                        compiled_class_hash: tx.compiled_class_hash,
                        signature: tx.signature,
                        nonce: tx.nonce,
                        class_hash,
                        resource_bounds: tx.resource_bounds,
                        tip: tx.tip,
                        paymaster_data: tx.paymaster_data,
                        account_deployment_data: tx.account_deployment_data,
                        nonce_data_availability_mode: tx.nonce_data_availability_mode,
                        fee_data_availability_mode: tx.fee_data_availability_mode,
                    }),
                    None,
                )
            }
            RpcTransaction::DeployAccount(RpcDeployAccountTransaction::V3(tx)) => {
                let contract_address = tx.calculate_contract_address()?;
                (
                    InternalRpcTransactionWithoutTxHash::DeployAccount(
                        InternalRpcDeployAccountTransaction {
                            tx: RpcDeployAccountTransaction::V3(tx),
                            contract_address,
                        },
                    ),
                    None,
                )
            }
        };
        let tx_hash = tx_without_hash.calculate_transaction_hash(&self.chain_id)?;
        Ok((InternalRpcTransaction { tx: tx_without_hash, tx_hash }, proof_data))
    }
```
