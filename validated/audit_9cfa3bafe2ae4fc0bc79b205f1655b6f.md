[1](#0-0) [2](#0-1)

### Citations

**File:** crates/sui-types/src/transaction_executor.rs (L20-43)
```rust
pub trait TransactionExecutor: Send + Sync {
    async fn execute_transaction(
        &self,
        request: ExecuteTransactionRequestV3,
        client_addr: Option<std::net::SocketAddr>,
    ) -> Result<ExecuteTransactionResponseV3, TransactionSubmissionError>;

    fn simulate_transaction(
        &self,
        transaction: TransactionData,
        checks: TransactionChecks,
        allow_mock_gas_coin: bool,
    ) -> Result<SimulateTransactionResult, SuiError>;
}

pub struct SimulateTransactionResult {
    pub effects: TransactionEffects,
    pub events: Option<TransactionEvents>,
    pub objects: ObjectSet,
    pub execution_result: Result<Vec<ExecutionResult>, ExecutionError>,
    pub mock_gas_id: Option<ObjectID>,
    pub unchanged_loaded_runtime_objects: Vec<ObjectKey>,
    pub suggested_gas_price: Option<u64>,
}
```
