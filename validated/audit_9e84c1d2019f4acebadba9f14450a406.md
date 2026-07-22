### Title
Hardcoded `paid_fee_on_l1 = Fee(1)` in Consensus L1 Handler Conversion Produces Wrong Receipt Data and Trivially Bypasses Blockifier Fee Check - (`File: crates/apollo_transaction_converter/src/transaction_converter.rs`)

### Summary

`TransactionConverter::convert_consensus_l1_handler_to_internal_l1_handler` unconditionally sets `paid_fee_on_l1 = Fee(1)` for every L1 handler transaction arriving through the consensus path. The blockifier's only fee guard for L1 handlers checks `paid_fee != Fee(0)`, so `Fee(1)` always passes. The actual fee paid on L1 is silently discarded, and the wrong value is committed to the central blob receipt.

### Finding Description

In `crates/apollo_transaction_converter/src/transaction_converter.rs` at line 473–483, the consensus-path conversion for L1 handler transactions fabricates the `paid_fee_on_l1` field:

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

The `ConsensusTransaction::L1Handler` variant carries only `transaction::L1HandlerTransaction`, which has no `paid_fee_on_l1` field, so the converter must supply one. It supplies the constant `Fee(1)` for every transaction, regardless of what was actually paid on L1.

The blockifier's fee enforcement for L1 handlers in `crates/blockifier/src/transaction/l1_handler_transaction.rs` only checks that the paid fee is non-zero:

```rust
if paid_fee == Fee(0) {
    return Err(TransactionExecutionError::TransactionFeeError(Box::new(
        TransactionFeeError::InsufficientFee { paid_fee, actual_fee: receipt.fee },
    )));
}
``` [2](#0-1) 

Because `Fee(1) != Fee(0)`, this guard is trivially satisfied for every L1 handler processed through the consensus path, regardless of the actual fee paid on L1.

The fabricated `paid_fee_on_l1` is then serialised into the `CentralL1HandlerTransaction` and written to the central blob:

```rust
impl From<L1HandlerTransaction> for CentralL1HandlerTransaction {
    fn from(tx: L1HandlerTransaction) -> CentralL1HandlerTransaction {
        CentralL1HandlerTransaction {
            ...
            paid_fee_on_l1: tx.paid_fee_on_l1,  // always Fee(1) from consensus path
        }
    }
}
``` [3](#0-2) 

The test fixture for the central blob confirms the expected value is `Fee(1)`: [4](#0-3) 

### Impact Explanation

Every L1 handler transaction executed through the consensus path will have `paid_fee_on_l1 = Fee(1)` in its receipt and in the central blob, regardless of the actual fee paid on L1. This is a wrong receipt value committed to persistent state. If the Starknet OS or any downstream verifier reads `paid_fee_on_l1` from the central blob to verify L1 fee payment, it will always see `1` instead of the real amount, producing an authoritative-looking wrong value. Additionally, the blockifier's defense-in-depth fee check — intended to reject zero-fee L1 handlers — is rendered meaningless for the consensus path.

This matches the allowed impact: **Wrong state, receipt, event, L1 message, class hash, storage value, or revert result from blockifier/syscall/execution logic for accepted input.**

### Likelihood Explanation

Every L1 handler transaction that passes through the consensus path (i.e., every L1→L2 message included in a consensus-proposed block) triggers this. No special attacker action is required; the bug fires unconditionally on normal protocol operation. The TODO comment in the source confirms this is a known placeholder that has not been resolved.

### Recommendation

The `ConsensusTransaction::L1Handler` variant should be extended to carry the `paid_fee_on_l1` field so that the actual value from the L1 scraper/feeder gateway is propagated through the consensus protocol and used in `convert_consensus_l1_handler_to_internal_l1_handler` instead of the hardcoded `Fee(1)`.

### Proof of Concept

1. An L1 user calls `sendMessageToL2` on the Starknet core contract, paying a real fee (e.g., `1 ETH`).
2. The L1 scraper picks up the event and creates an `L1HandlerTransaction` with `paid_fee_on_l1 = Fee(1_000_000_000_000_000_000)`.
3. The transaction is included in a consensus proposal as `ConsensusTransaction::L1Handler(raw_tx)` — the `paid_fee_on_l1` is not carried in this type.
4. A validator calls `convert_consensus_tx_to_internal_consensus_tx`, which calls `convert_consensus_l1_handler_to_internal_l1_handler`.
5. The resulting `executable_transaction::L1HandlerTransaction` has `paid_fee_on_l1 = Fee(1)`.
6. The blockifier executes the transaction; `paid_fee == Fee(1) != Fee(0)` so the fee check passes.
7. The central blob records `paid_fee_on_l1: 0x1` instead of `0xde0b6b3a7640000`.
8. Any system reading the receipt (OS, prover, explorer) sees the wrong fee value. [5](#0-4) [6](#0-5)

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

**File:** crates/apollo_consensus_orchestrator/src/cende/central_objects_test.rs (L381-396)
```rust
fn l1_handler_tx() -> L1HandlerTransaction {
    L1HandlerTransaction {
        tx: starknet_api::transaction::L1HandlerTransaction {
            version: TransactionVersion::ZERO,
            nonce: nonce!(1),
            contract_address: contract_address!(
                "0x14abfd58671a1a9b30de2fcd2a42e8bff2ce1096a7c70bc7995904965f277e"
            ),
            entry_point_selector: EntryPointSelector(felt!("0x2a")),
            calldata: Calldata(Arc::new(vec![felt!(0_u8), felt!(1_u8)])),
        },
        tx_hash: TransactionHash(felt!(
            "0xc947753befd252ca08042000cd6d783162ee2f5df87b519ddf3081b9b4b997"
        )),
        paid_fee_on_l1: Fee(1),
    }
```
