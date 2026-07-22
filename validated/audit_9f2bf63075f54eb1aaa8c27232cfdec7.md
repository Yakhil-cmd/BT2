### Title
Hardcoded Placeholder `Fee(1)` for `paid_fee_on_l1` in Consensus L1 Handler Conversion Produces Wrong Receipt Data - (File: crates/apollo_transaction_converter/src/transaction_converter.rs)

### Summary
`TransactionConverter::convert_consensus_l1_handler_to_internal_l1_handler` unconditionally supplies `Fee(1)` as the `paid_fee_on_l1` field for every L1 handler transaction that enters the sequencer through the consensus path. This is an acknowledged placeholder (marked with a `TODO`). Because the blockifier's only fee guard for L1 handlers checks `paid_fee != Fee(0)`, the placeholder passes silently, and the wrong value propagates into the `CentralL1HandlerTransaction` receipt that is serialised and forwarded to the prover/Cende layer.

### Finding Description
In `convert_consensus_l1_handler_to_internal_l1_handler`:

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
``` [1](#0-0) 

The `paid_fee_on_l1` field is the fee actually paid on the L1 Starknet core contract for the L1→L2 message. The `ConsensusTransaction::L1Handler` variant carries only the raw `transaction::L1HandlerTransaction` (no fee field), so the converter has no source for the real value and substitutes `Fee(1)`.

The blockifier's fee guard for L1 handlers is:

```rust
if paid_fee == Fee(0) {
    return Err(TransactionExecutionError::TransactionFeeError(...));
}
``` [2](#0-1) 

`Fee(1)` is non-zero, so the guard passes unconditionally for every L1 handler transaction arriving through the consensus path. The wrong value then flows into `CentralL1HandlerTransaction::paid_fee_on_l1`:

```rust
impl From<L1HandlerTransaction> for CentralL1HandlerTransaction {
    fn from(tx: L1HandlerTransaction) -> CentralL1HandlerTransaction {
        CentralL1HandlerTransaction {
            ...
            paid_fee_on_l1: tx.paid_fee_on_l1,  // always Fee(1)
        }
    }
}
``` [3](#0-2) 

### Impact Explanation
Every L1 handler transaction sequenced through the consensus path carries `paid_fee_on_l1 = 1` in the receipt/central-objects payload forwarded to the prover and Cende layer, regardless of the actual fee paid on L1. This is a wrong receipt value for accepted input, matching the "Critical – wrong receipt … from blockifier/syscall/execution logic for accepted input" criterion. If the OS or prover uses `paid_fee_on_l1` to verify economic correctness of the block (e.g. in block-hash computation or fee-accounting hints), the mismatch will produce an incorrect or unverifiable block.

### Likelihood Explanation
The code path is exercised for every L1 handler transaction that enters via `convert_consensus_tx_to_internal_consensus_tx`. No special attacker action is required; normal L1→L2 messaging triggers it. The TODO comment confirms the placeholder is intentional but unresolved.

### Recommendation
The `ConsensusTransaction::L1Handler` variant should carry the `paid_fee_on_l1` value sourced from the L1 event scraper so that `convert_consensus_l1_handler_to_internal_l1_handler` can pass the real fee instead of the hardcoded `Fee(1)`. Until that is done, the field should at minimum be validated against the actual L1 event data before the transaction is admitted to the block.

### Proof of Concept
1. Submit any L1→L2 message on L1 with a non-trivial fee (e.g. 1 ETH).
2. The sequencer's L1 event scraper picks up the event and wraps it as `ConsensusTransaction::L1Handler`.
3. `convert_consensus_tx_to_internal_consensus_tx` calls `convert_consensus_l1_handler_to_internal_l1_handler`, which sets `paid_fee_on_l1 = Fee(1)`.
4. The blockifier executes the transaction; the `paid_fee != Fee(0)` check passes.
5. The resulting `CentralL1HandlerTransaction` serialised to Cende contains `"paid_fee_on_l1": "0x1"` instead of the actual fee, producing a wrong receipt for the block. [1](#0-0) [4](#0-3) [5](#0-4)

### Citations

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

**File:** crates/blockifier/src/transaction/l1_handler_transaction.rs (L100-113)
```rust
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
