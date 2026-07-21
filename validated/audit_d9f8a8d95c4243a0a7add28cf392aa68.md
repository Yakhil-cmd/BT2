### Title
Hardcoded `Fee(1)` for `paid_fee_on_l1` in Consensus L1 Handler Conversion Produces Wrong Receipt Value - (File: crates/apollo_transaction_converter/src/transaction_converter.rs)

### Summary

`TransactionConverter::convert_consensus_l1_handler_to_internal_l1_handler` unconditionally supplies `Fee(1)` as `paid_fee_on_l1` when converting a consensus-path L1 handler transaction into its executable form. This is the direct Starknet analog of the Bitcoin adapter's hardcoded `transferFee = 10_000`: a placeholder constant acknowledged by a TODO comment replaces a value that must reflect real on-chain data.

### Finding Description

In the consensus validator path, every `ConsensusTransaction::L1Handler` is converted via:

```rust
// crates/apollo_transaction_converter/src/transaction_converter.rs:473-483
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

The `paid_fee_on_l1` field is the ETH fee the L1 sender paid to the Starknet core contract when submitting the `LogMessageToL2` event. The proposer path reads this value from the L1 scraper and stores it in the `L1HandlerTransaction`. The validator path, however, discards whatever the proposer observed and substitutes `Fee(1)` for every L1 handler transaction it processes.

The blockifier's fee adequacy check for L1 handlers is:

```rust
// crates/blockifier/src/transaction/l1_handler_transaction.rs:103-113
let paid_fee = self.paid_fee_on_l1;
// For now, assert only that any amount of fee was paid.
if paid_fee == Fee(0) {
    return Err(TransactionExecutionError::TransactionFeeError(...));
}
``` [2](#0-1) 

Because `Fee(1) != Fee(0)`, the hardcoded value always satisfies this guard. The incorrect `paid_fee_on_l1` then propagates into `CentralL1HandlerTransaction` (the struct serialised and sent to the prover/cende):

```rust
// crates/apollo_consensus_orchestrator/src/cende/central_objects.rs:383-393
impl From<L1HandlerTransaction> for CentralL1HandlerTransaction {
    fn from(tx: L1HandlerTransaction) -> CentralL1HandlerTransaction {
        CentralL1HandlerTransaction {
            ...
            paid_fee_on_l1: tx.paid_fee_on_l1,  // always 1 on validator nodes
            ...
        }
    }
}
``` [3](#0-2) 

### Impact Explanation

Every validator node commits blocks in which every L1 handler transaction carries `paid_fee_on_l1 = 1` regardless of the actual ETH value locked in the Starknet core contract. This produces:

1. **Wrong receipt/block data**: The committed block's L1 handler records contain an incorrect `paid_fee_on_l1`, diverging from the proposer's view and from the actual L1 event.
2. **Bypassed fee adequacy check**: The only guard against a zero-fee L1 handler (`paid_fee == Fee(0)`) is trivially satisfied by the hardcoded `Fee(1)`, meaning a proposer could theoretically include an L1 handler with `paid_fee_on_l1 = 0` and the validator would still accept it.
3. **Prover/cende data corruption**: The `paid_fee_on_l1` field sent to the prover is always `1`, not the real ETH amount, which can cause proof mismatches if the prover cross-checks against L1 event data.

Fits: **High – Transaction conversion logic binds the wrong executable payload** and **Critical – Wrong receipt/L1 message value from execution logic for accepted input**.

### Likelihood Explanation

This code is on the hot path for every L1 handler transaction processed by a validator node. The TODO comment confirms the team is aware the value is a placeholder. Every block containing an L1 handler transaction triggers the issue.

### Recommendation

Replace the hardcoded `Fee(1)` with the actual `paid_fee_on_l1` value. The `ConsensusTransaction::L1Handler` type should carry the fee paid on L1 (sourced from the L1 scraper), and `convert_consensus_l1_handler_to_internal_l1_handler` should forward it instead of substituting a constant.

### Proof of Concept

1. L1 scraper observes a `LogMessageToL2` event with `msg.value = 500_000 wei` and stores `paid_fee_on_l1 = Fee(500_000)` in the proposer's `L1HandlerTransaction`.
2. Proposer includes the transaction in a block proposal; its executable form has `paid_fee_on_l1 = Fee(500_000)`.
3. Validator receives `ConsensusTransaction::L1Handler(raw_tx)` and calls `convert_consensus_l1_handler_to_internal_l1_handler`, producing `paid_fee_on_l1 = Fee(1)`.
4. Blockifier executes the transaction; `Fee(1) != Fee(0)` so the fee check passes.
5. `CentralL1HandlerTransaction { paid_fee_on_l1: Fee(1), ... }` is serialised and sent to the prover — the actual `500_000 wei` is lost.
6. The committed block on the validator contains `paid_fee_on_l1 = 1` for every L1 handler, diverging from the proposer's committed value and from the L1 ground truth. [1](#0-0) [4](#0-3) [3](#0-2)

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

**File:** crates/blockifier/src/transaction/l1_handler_transaction.rs (L100-115)
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

                        Ok(l1_handler_tx_execution_info(execute_call_info, receipt, None))
```

**File:** crates/apollo_consensus_orchestrator/src/cende/central_objects.rs (L383-393)
```rust
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
