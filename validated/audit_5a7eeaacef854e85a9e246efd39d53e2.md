### Title
Hardcoded `paid_fee_on_l1 = Fee(1)` in Consensus L1 Handler Conversion Produces Wrong Receipt Value in Central Blob - (File: crates/apollo_transaction_converter/src/transaction_converter.rs)

### Summary
`TransactionConverter::convert_consensus_l1_handler_to_internal_l1_handler` unconditionally sets `paid_fee_on_l1` to the placeholder `Fee(1)` for every L1 handler transaction processed through the consensus path. The actual fee paid on L1 is discarded. This wrong value is serialized into the central blob sent to the OS for proving, producing an authoritative-looking but incorrect receipt field for every L1 handler transaction sequenced through consensus.

### Finding Description

`convert_consensus_l1_handler_to_internal_l1_handler` is called whenever a validator converts a `ConsensusTransaction::L1Handler` into an executable transaction: [1](#0-0) 

The `Fee(1)` placeholder is then stored in `executable_transaction::L1HandlerTransaction::paid_fee_on_l1`: [2](#0-1) 

The blockifier's fee check for L1 handlers only tests `paid_fee != Fee(0)`: [3](#0-2) 

Because `Fee(1) != Fee(0)`, the check trivially passes regardless of what was actually paid on L1. The `paid_fee_on_l1` field is then serialized into `CentralL1HandlerTransaction` for the central blob: [4](#0-3) 

The central blob is the authoritative input to the OS prover. Every L1 handler transaction processed through consensus will carry `paid_fee_on_l1 = 1` in the blob, regardless of the actual ETH fee paid on L1.

### Impact Explanation

The `paid_fee_on_l1` field in the central blob is a receipt value that the OS prover uses to reconstruct and verify the block. Emitting a hardcoded `Fee(1)` instead of the real value produces a wrong receipt for every L1 handler transaction sequenced through consensus. This matches the "wrong receipt" impact category. Additionally, the blockifier's only guard against zero-fee L1 handler execution is the `paid_fee == Fee(0)` check; the hardcoded `Fee(1)` permanently bypasses this guard, meaning the check provides no real protection in the consensus path.

### Likelihood Explanation

Every L1 handler transaction that passes through the consensus conversion path triggers this code path unconditionally. There is no configuration flag or fallback. The TODO comment confirms the developers are aware the value is a placeholder, meaning the issue is present in all current production deployments.

### Recommendation

The `paid_fee_on_l1` value must be sourced from the actual L1 scraper data rather than hardcoded. The `ConsensusTransaction::L1Handler` type (or the internal consensus transaction type) should carry the real `paid_fee_on_l1` field so that `convert_consensus_l1_handler_to_internal_l1_handler` can propagate it faithfully. Until the real value is available, the function should at minimum return an error rather than silently substituting a placeholder that bypasses the fee check and corrupts the central blob.

### Proof of Concept

1. An L1 user sends a message to L2 via the Starknet core contract on Ethereum, paying a large ETH fee (e.g., `Fee(1_000_000_000)`).
2. The L1 scraper picks up the message and includes it as a `ConsensusTransaction::L1Handler` in a block proposal.
3. A validating node calls `convert_consensus_tx_to_internal_consensus_tx`, which calls `convert_consensus_l1_handler_to_internal_l1_handler`.
4. The resulting `executable_transaction::L1HandlerTransaction` has `paid_fee_on_l1 = Fee(1)` instead of `Fee(1_000_000_000)`.
5. The blockifier check `if paid_fee == Fee(0)` passes silently.
6. `CentralL1HandlerTransaction::from` serializes `paid_fee_on_l1: Fee(1)` into the central blob.
7. The OS prover receives a central blob where every L1 handler transaction reports `paid_fee_on_l1 = 1`, regardless of the actual ETH paid on L1. [5](#0-4) [1](#0-0) [6](#0-5) [7](#0-6)

### Citations

**File:** crates/apollo_transaction_converter/src/transaction_converter.rs (L184-201)
```rust
    async fn convert_consensus_tx_to_internal_consensus_tx(
        &self,
        tx: ConsensusTransaction,
    ) -> TransactionConverterResult<(InternalConsensusTransaction, Option<VerifyAndStoreProofTask>)>
    {
        match tx {
            ConsensusTransaction::RpcTransaction(tx) => {
                let (internal_tx, proof_data) = self.convert_rpc_tx_to_internal(tx).await?;
                let task = proof_data.map(|(proof_facts, proof)| {
                    self.spawn_verify_and_store_proof(proof_facts, proof)
                });
                Ok((InternalConsensusTransaction::RpcTransaction(internal_tx), task))
            }
            ConsensusTransaction::L1Handler(tx) => {
                let internal_tx = self.convert_consensus_l1_handler_to_internal_l1_handler(tx)?;
                Ok((InternalConsensusTransaction::L1Handler(internal_tx), None))
            }
        }
```

**File:** crates/apollo_transaction_converter/src/transaction_converter.rs (L473-483)
```rust
    fn convert_consensus_l1_handler_to_internal_l1_handler(
        &self,
        tx: transaction::L1HandlerTransaction,
    ) -> TransactionConverterResult<executable_transaction::L1HandlerTransaction> {
        Ok(executable_transaction::L1HandlerTransaction::create(
            tx,
            &self.chain_id,
            // TODO(Gilad): Change this once we put real value in paid_fee_on_l1.
            Fee(1),
        )?)
    }
```

**File:** crates/starknet_api/src/executable_transaction.rs (L380-406)
```rust
#[derive(Clone, Debug, Default, Deserialize, Eq, PartialEq, Serialize, Hash)]
pub struct L1HandlerTransaction {
    pub tx: crate::transaction::L1HandlerTransaction,
    pub tx_hash: TransactionHash,
    pub paid_fee_on_l1: Fee,
}

impl L1HandlerTransaction {
    pub const L1_HANDLER_TYPE_NAME: &str = "L1_HANDLER";

    pub fn create(
        raw_tx: crate::transaction::L1HandlerTransaction,
        chain_id: &ChainId,
        paid_fee_on_l1: Fee,
    ) -> Result<L1HandlerTransaction, StarknetApiError> {
        let tx_hash = raw_tx.calculate_transaction_hash(chain_id, &raw_tx.version)?;
        Ok(Self { tx: raw_tx, tx_hash, paid_fee_on_l1 })
    }

    pub fn payload_size(&self) -> usize {
        // The calldata includes the "from" field, which is not a part of the payload.
        // `saturating_sub` guards the empty-calldata case (which would otherwise underflow to
        // `usize::MAX` in release): `L1HandlerTransaction` derives `Deserialize` and `Calldata`
        // has no non-empty invariant.
        self.tx.calldata.0.len().saturating_sub(1)
    }
}
```

**File:** crates/blockifier/src/transaction/l1_handler_transaction.rs (L98-115)
```rust
                    Ok(()) => {
                        // Post-execution check passed, commit the execution.
                        execution_state.commit();
                        // TODO(Arni): Consider removing this check. It is covered by the starknet
                        // core contract.
                        let paid_fee = self.paid_fee_on_l1;
                        // For now, assert only that any amount of fee was paid.
                        // The error message still indicates the required fee.
                        if paid_fee == Fee(0) {
                            return Err(TransactionExecutionError::TransactionFeeError(Box::new(
                                TransactionFeeError::InsufficientFee {
                                    paid_fee,
                                    actual_fee: receipt.fee,
                                },
                            )));
                        }

                        Ok(l1_handler_tx_execution_info(execute_call_info, receipt, None))
```

**File:** crates/apollo_consensus_orchestrator/src/cende/central_objects.rs (L374-393)
```rust
struct CentralL1HandlerTransaction {
    contract_address: ContractAddress,
    entry_point_selector: EntryPointSelector,
    calldata: Calldata,
    nonce: Nonce,
    paid_fee_on_l1: Fee,
    hash_value: TransactionHash,
}

impl From<L1HandlerTransaction> for CentralL1HandlerTransaction {
    fn from(tx: L1HandlerTransaction) -> CentralL1HandlerTransaction {
        CentralL1HandlerTransaction {
            hash_value: tx.tx_hash,
            contract_address: tx.tx.contract_address,
            entry_point_selector: tx.tx.entry_point_selector,
            calldata: tx.tx.calldata,
            nonce: tx.tx.nonce,
            paid_fee_on_l1: tx.paid_fee_on_l1,
        }
    }
```
