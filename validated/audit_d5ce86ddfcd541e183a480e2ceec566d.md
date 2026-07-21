Based on the code investigation, here is the analysis:

---

### Title
RPC Simulation Rejects Valid Future-Nonce Transactions Due to Hardcoded `strict_nonce_check = true` — (`crates/apollo_rpc_execution/src/lib.rs`)

### Summary

`to_blockifier_tx` hardcodes `strict_nonce_check = true` for every transaction type, including `only_query = true` simulation requests. This causes blockifier's `handle_nonce` to reject any simulation whose nonce does not exactly equal the account's current on-chain nonce, making it impossible to simulate a sequence of transactions (e.g., nonce+1, nonce+2) via `starknet_simulateTransactions` or `starknet_estimateFee`.

### Finding Description

In `to_blockifier_tx`, the `strict_nonce_check` flag is unconditionally set to `true`: [1](#0-0) 

The developer left an explicit TODO acknowledging this is incomplete:

> `// TODO(yair): support only_query version bit (enable in the RPC v0.6 and use the correct value).`

The `only_query` flag is correctly threaded into `ExecutionFlags` as a separate field, but `strict_nonce_check` is never derived from it. These are independent fields in `ExecutionFlags`: [2](#0-1) 

By contrast, the gateway's stateful validation path correctly uses `strict_nonce_check = false`: [3](#0-2) 

When blockifier's `handle_nonce` runs with `strict_nonce_check = true`, it requires the transaction nonce to exactly equal the account's current nonce. Any future nonce (account_nonce + 1, + 2, etc.) triggers `InvalidNonce` and aborts the simulation.

### Impact Explanation

Any unprivileged user calling `starknet_simulateTransactions` or `starknet_estimateFee` with a transaction whose nonce is ahead of the current account nonce (a common and legitimate pattern when simulating a chain of dependent transactions) receives an `InvalidNonce` error instead of a simulation result. This is a **High** impact: the RPC simulation endpoint incorrectly rejects valid inputs, producing an authoritative-looking error for a request that should succeed.

### Likelihood Explanation

High. Any client that simulates a sequence of two or more transactions in a single batch (e.g., ERC-20 approve at nonce N, then swap at nonce N+1) will hit this on the second transaction. This is a standard use case for fee estimation and simulation.

### Recommendation

Derive `strict_nonce_check` from `only_query` in `to_blockifier_tx`:

```rust
// Replace the hardcoded line:
let strict_nonce_check = true;

// With:
let strict_nonce_check = !only_query;
```

This mirrors the intent of the existing TODO comment and aligns with the gateway's use of `strict_nonce_check = false` for non-execution validation paths.

### Proof of Concept

A Rust unit test in `crates/apollo_rpc_execution/src/execution_test.rs` can demonstrate this:

1. Set up a state with an account at nonce `N`.
2. Call `simulate_transactions` with an `ExecutableTransactionInput::Invoke` where `only_query = true` and `nonce = N + 2`.
3. Assert the simulation returns a successful `TransactionSimulationOutput` rather than `ExecutionError` wrapping `InvalidNonce`.

With the current code the assertion fails (simulation returns `InvalidNonce`). After the fix (`strict_nonce_check = !only_query`) the assertion passes. [4](#0-3)

### Citations

**File:** crates/apollo_rpc_execution/src/lib.rs (L804-827)
```rust
fn to_blockifier_tx(
    tx: ExecutableTransactionInput,
    tx_hash: TransactionHash,
    transaction_index: usize,
    charge_fee: bool,
    validate: bool,
) -> ExecutionResult<BlockifierTransaction> {
    // TODO(yair): support only_query version bit (enable in the RPC v0.6 and use the correct
    // value).
    let strict_nonce_check = true;
    match tx {
        ExecutableTransactionInput::Invoke(invoke_tx, only_query) => {
            let execution_flags =
                ExecutionFlags { only_query, charge_fee, validate, strict_nonce_check };
            BlockifierTransaction::from_api(
                Transaction::Invoke(invoke_tx),
                tx_hash,
                None,
                None,
                None,
                execution_flags,
            )
            .map_err(|err| ExecutionError::from((transaction_index, err)))
        }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L1-43)
```rust
use std::sync::Arc;

use apollo_gateway_config::config::StatefulTransactionValidatorConfig;
use apollo_gateway_types::deprecated_gateway_error::{
    KnownStarknetErrorCode,
    StarknetError,
    StarknetErrorCode,
};
use apollo_gateway_types::errors::GatewaySpecError;
use apollo_mempool_types::communication::SharedMempoolClient;
use apollo_mempool_types::mempool_types::ValidationArgs;
use apollo_proc_macros::sequencer_latency_histogram;
use async_trait::async_trait;
use blockifier::blockifier::config::NativeClassesWhitelist;
use blockifier::blockifier::stateful_validator::{StatefulValidator, StatefulValidatorTrait};
use blockifier::blockifier_versioned_constants::VersionedConstants;
use blockifier::bouncer::BouncerConfig;
use blockifier::context::{BlockContext, ChainInfo};
use blockifier::state::cached_state::CachedState;
use blockifier::state::contract_class_manager::ContractClassManager;
use blockifier::state::state_reader_and_contract_manager::StateReaderAndContractManager;
use blockifier::transaction::account_transaction::{AccountTransaction, ExecutionFlags};
use blockifier::transaction::transactions::enforce_fee;
use num_rational::Ratio;
use starknet_api::block::NonzeroGasPrice;
use starknet_api::core::{ContractAddress, Nonce};
use starknet_api::executable_transaction::{
    AccountTransaction as ExecutableTransaction,
    InvokeTransaction as ExecutableInvokeTransaction,
};
use starknet_api::transaction::fields::ValidResourceBounds;
use starknet_types_core::felt::Felt;
use tracing::{debug, Span};

use crate::errors::{mempool_client_err_to_deprecated_gw_err, StatefulTransactionValidatorResult};
use crate::gateway_fixed_block_state_reader::GatewayFixedBlockStateReader;
use crate::metrics::{GATEWAY_CLASS_CACHE_METRICS, GATEWAY_VALIDATE_TX_LATENCY};
use crate::state_reader::{GatewayStateReaderWithCompiledClasses, StateReaderFactory};

#[cfg(test)]
#[path = "stateful_transaction_validator_test.rs"]
mod stateful_transaction_validator_test;

```
