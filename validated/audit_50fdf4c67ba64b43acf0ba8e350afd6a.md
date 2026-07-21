### Title
Gateway L2 Gas Price Admission Uses Stale `l2_gas_price` Instead of `next_l2_gas_price`, Causing Admitted Transactions to Fail at Execution - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The gateway's stateful resource-bounds check validates a transaction's `l2_gas.max_price_per_unit` against the **current finalized block's** `l2_gas_price`. However, the blockifier executes the transaction in the **next block**, whose gas price is `next_l2_gas_price` (already computed and stored in the block header via EIP-1559). When the network is busy and `next_l2_gas_price > l2_gas_price`, transactions that pass gateway admission will fail at blockifier execution with `MaxGasPriceTooLow`. The code itself acknowledges this with a TODO comment at the exact line.

---

### Finding Description

**Step 1 – Gateway admission** (`validate_resource_bounds`, line 229):

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    .await?
    .gas_prices
    .strk_gas_prices
    .l2_gas_price;          // ← block_N.l2_gas_price
```

The check is: `tx.l2_gas.max_price_per_unit >= (min_gas_price_percentage / 100) * block_N.l2_gas_price`.

Production config sets `min_gas_price_percentage = 100`, so the effective gate is: `max_price >= block_N.l2_gas_price`. [1](#0-0) [2](#0-1) 

**Step 2 – Blockifier execution** (`run_validate_entry_point`, line 323):

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next(); // N → N+1
// gas_prices are NOT updated — still block_N prices
let block_context = BlockContext::new(block_info, ...);
```

The block number is advanced to N+1, but the gas prices remain those of block N. So `check_fee_bounds` inside `run_validate_entry_point` also uses block N's prices — it does **not** catch the mismatch. [3](#0-2) 

**Step 3 – Actual batcher execution** uses `block_N.next_l2_gas_price` (the EIP-1559-derived price for block N+1, stored in the block header):

```rust
next_l2_gas_price: self.l2_gas_price,   // set by calculate_next_l2_gas_price()
``` [4](#0-3) 

`check_fee_bounds` in the batcher then checks `tx.max_price_per_unit >= block_N.next_l2_gas_price`: [5](#0-4) 

**The gap:** When the block is above the gas target, `next_l2_gas_price > l2_gas_price` (EIP-1559 can increase the price by up to ~12.5% per block). Any transaction with `max_price_per_unit` in the range `[block_N.l2_gas_price, block_N.next_l2_gas_price)` passes gateway admission but fails at blockifier execution with `MaxGasPriceTooLow`. The inverse also holds: when the block is under-utilized, `next_l2_gas_price < l2_gas_price`, and the gateway rejects transactions that would succeed at execution.

The `next_l2_gas_price` is already available in the block header: [6](#0-5) 

---

### Impact Explanation

**High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

- **Admitted-but-failing path**: Under load (block above gas target), transactions with `max_price_per_unit == block_N.l2_gas_price` pass the gateway's 100%-threshold check but fail at blockifier execution with `MaxGasPriceTooLow`. These transactions consume mempool slots and batcher processing time without ever executing.
- **Rejected-but-valid path**: When the block is under-utilized, `next_l2_gas_price < l2_gas_price`. The gateway rejects transactions with `max_price_per_unit` in `[next_l2_gas_price, l2_gas_price)` even though they would succeed at execution.

Both directions are reachable by any unprivileged user submitting a V3 (`AllResources`) transaction.

---

### Likelihood Explanation

High. The EIP-1559 price adjustment runs every block. With `min_gas_price_percentage = 100` in production, the admission threshold is exactly `block_N.l2_gas_price`. Any block that is above or below the gas target causes `next_l2_gas_price ≠ l2_gas_price`, triggering the mismatch. The code's own TODO comment (`// TODO(Arni): getnext_l2_gas_price from the block header.`) confirms the developers are aware of the wrong reference value. [7](#0-6) [8](#0-7) 

---

### Recommendation

Replace the `l2_gas_price` read in `validate_resource_bounds` with `next_l2_gas_price` from the block header, which is the price that will actually be used when the transaction executes:

```rust
// Before (wrong):
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    .await?
    .gas_prices
    .strk_gas_prices
    .l2_gas_price;

// After (correct):
// Expose next_l2_gas_price through GatewayFixedBlockStateReader and use it here.
```

Similarly, in `run_validate_entry_point`, after advancing `block_info.block_number` to N+1, update `block_info.gas_prices` to reflect the next block's prices (using `next_l2_gas_price` from the header), so the blockifier's `check_fee_bounds` at gateway time is consistent with what the batcher will enforce.

---

### Proof of Concept

1. Observe the current finalized block N with `l2_gas_price = P` and `next_l2_gas_price = P' > P` (block is above gas target).
2. Submit a V3 invoke transaction with `l2_gas.max_price_per_unit = P` (exactly equal to `l2_gas_price`).
3. Gateway `validate_resource_bounds` checks `P >= 100% * P` → **passes**.
4. Gateway `run_validate_entry_point` builds a block context with block number N+1 but gas price P → `check_fee_bounds` checks `P >= P` → **passes**.
5. Transaction is admitted to the mempool.
6. Batcher builds block N+1 with gas price P'. `check_fee_bounds` checks `P >= P'` → **fails** with `MaxGasPriceTooLow`.
7. Transaction is reverted or dropped; the gateway's admission decision was incorrect. [9](#0-8) [10](#0-9)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L158-179)
```rust
    async fn extract_state_nonce_and_run_validations(
        &mut self,
        executable_tx: &ExecutableTransaction,
        mempool_client: SharedMempoolClient,
    ) -> StatefulTransactionValidatorResult<Nonce> {
        let account_nonce =
            self.get_nonce_from_state(executable_tx.contract_address()).await.map_err(|e| {
                // TODO(noamsp): Fix this. Need to map the errors better.
                StarknetError::internal_with_signature_logging(
                    format!(
                        "Failed to get nonce for sender address {}",
                        executable_tx.contract_address()
                    ),
                    &executable_tx.signature(),
                    e,
                )
            })?;
        let skip_validate =
            self.run_pre_validation_checks(executable_tx, account_nonce, mempool_client).await?;
        self.run_validate_entry_point(executable_tx, skip_validate).await?;
        Ok(account_nonce)
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L223-243)
```rust
    async fn validate_resource_bounds(
        &self,
        executable_tx: &ExecutableTransaction,
    ) -> StatefulTransactionValidatorResult<()> {
        // Skip this validation during the systems bootstrap phase.
        if self.config.validate_resource_bounds {
            // TODO(Arni): getnext_l2_gas_price from the block header.
            let previous_block_l2_gas_price = self
                .gateway_fixed_block_state_reader
                .get_block_info()
                .await?
                .gas_prices
                .strk_gas_prices
                .l2_gas_price;
            self.validate_tx_l2_gas_price_within_threshold(
                executable_tx.resource_bounds(),
                previous_block_l2_gas_price,
            )?;
        }
        Ok(())
    }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L302-330)
```rust
    #[sequencer_latency_histogram(GATEWAY_VALIDATE_TX_LATENCY, true)]
    async fn run_validate_entry_point(
        &mut self,
        executable_tx: &ExecutableTransaction,
        skip_validate: bool,
    ) -> StatefulTransactionValidatorResult<()> {
        let only_query = false;
        let charge_fee = enforce_fee(executable_tx, only_query);
        let strict_nonce_check = false;
        let execution_flags =
            ExecutionFlags { only_query, charge_fee, validate: !skip_validate, strict_nonce_check };

        let account_tx = AccountTransaction { tx: executable_tx.clone(), execution_flags };

        // Build block context.
        let mut versioned_constants = VersionedConstants::get_versioned_constants(
            self.config.versioned_constants_overrides.clone(),
        );
        // The validation of a transaction is not affected by the casm hash migration.
        versioned_constants.disable_casm_hash_migration();

        let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        block_info.block_number = block_info.block_number.unchecked_next();
        let block_context = BlockContext::new(
            block_info,
            self.chain_info.clone(),
            versioned_constants,
            BouncerConfig::max(),
        );
```

**File:** crates/apollo_deployments/resources/app_configs/gateway_config.json (L19-19)
```json
  "gateway_config.static_config.stateful_tx_validator_config.min_gas_price_percentage": 100,
```

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L399-412)
```rust
        let block_header_without_hash = BlockHeaderWithoutHash {
            block_number: height,
            l1_gas_price,
            l1_data_gas_price,
            l2_gas_price,
            l2_gas_consumed: l2_gas_used,
            next_l2_gas_price: self.l2_gas_price,
            sequencer,
            timestamp: BlockTimestamp(init.timestamp),
            l1_da_mode: init.l1_da_mode,
            fee_proposal_fri: init.fee_proposal_fri,
            // TODO(guy.f): Figure out where/if to get the values below from and fill them.
            ..Default::default()
        };
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L374-458)
```rust
    fn check_fee_bounds(
        &self,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let minimal_gas_amount_vector = estimate_minimal_gas_vector(
            &tx_context.block_context,
            self,
            &tx_context.get_gas_vector_computation_mode(),
        );
        let TransactionContext { block_context, tx_info } = tx_context;
        let block_info = &block_context.block_info;
        let fee_type = &tx_info.fee_type();
        match tx_info {
            TransactionInfo::Current(context) => {
                let resources_amount_tuple = match &context.resource_bounds {
                    ValidResourceBounds::L1Gas(l1_gas_resource_bounds) => vec![(
                        L1Gas,
                        l1_gas_resource_bounds,
                        minimal_gas_amount_vector.to_l1_gas_for_fee(
                            tx_context.get_gas_prices(),
                            &tx_context.block_context.versioned_constants,
                        ),
                        block_info.gas_prices.l1_gas_price(fee_type),
                    )],
                    ValidResourceBounds::AllResources(AllResourceBounds {
                        l1_gas: l1_gas_resource_bounds,
                        l2_gas: l2_gas_resource_bounds,
                        l1_data_gas: l1_data_gas_resource_bounds,
                    }) => {
                        let GasPriceVector { l1_gas_price, l1_data_gas_price, l2_gas_price } =
                            block_info.gas_prices.gas_price_vector(fee_type);
                        vec![
                            (
                                L1Gas,
                                l1_gas_resource_bounds,
                                minimal_gas_amount_vector.l1_gas,
                                *l1_gas_price,
                            ),
                            (
                                L1DataGas,
                                l1_data_gas_resource_bounds,
                                minimal_gas_amount_vector.l1_data_gas,
                                *l1_data_gas_price,
                            ),
                            (
                                L2Gas,
                                l2_gas_resource_bounds,
                                minimal_gas_amount_vector.l2_gas,
                                *l2_gas_price,
                            ),
                        ]
                    }
                };
                let insufficiencies = resources_amount_tuple
                    .iter()
                    .flat_map(
                        |(resource, resource_bounds, minimal_gas_amount, actual_gas_price)| {
                            let mut insufficiencies_resource = vec![];
                            if minimal_gas_amount > &resource_bounds.max_amount {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasAmountTooLow {
                                        resource: *resource,
                                        max_gas_amount: resource_bounds.max_amount,
                                        minimal_gas_amount: *minimal_gas_amount,
                                    },
                                );
                            }
                            if resource_bounds.max_price_per_unit < actual_gas_price.get() {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasPriceTooLow {
                                        resource: *resource,
                                        max_gas_price: resource_bounds.max_price_per_unit,
                                        actual_gas_price: (*actual_gas_price).into(),
                                    },
                                );
                            }
                            insufficiencies_resource
                        },
                    )
                    .collect::<Vec<_>>();
                if !insufficiencies.is_empty() {
                    return Err(Box::new(TransactionFeeError::InsufficientResourceBounds {
                        errors: insufficiencies,
                    }))?;
                }
```

**File:** crates/apollo_storage/src/header.rs (L71-113)
```rust
/// Storage representation of a Starknet block header.
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, PartialOrd, Ord)]
pub struct StorageBlockHeader {
    /// The hash of this block.
    pub block_hash: BlockHash,
    /// The hash of this block's parent.
    pub parent_hash: BlockHash,
    /// The number of this block.
    pub block_number: BlockNumber,
    /// The L1 gas price per token.
    pub l1_gas_price: GasPricePerToken,
    /// The L1 data gas price per token.
    pub l1_data_gas_price: GasPricePerToken,
    /// The L2 gas price per token.
    pub l2_gas_price: GasPricePerToken,
    /// The amount of L2 gas consumed.
    pub l2_gas_consumed: GasAmount,
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
    /// The state root after this block.
    pub state_root: GlobalRoot,
    /// The sequencer address that created this block.
    pub sequencer: SequencerContractAddress,
    /// The timestamp of this block.
    pub timestamp: BlockTimestamp,
    /// The L1 data availability mode.
    pub l1_da_mode: L1DataAvailabilityMode,
    /// The state diff commitment, if available.
    pub state_diff_commitment: Option<StateDiffCommitment>,
    /// The transaction commitment, if available.
    pub transaction_commitment: Option<TransactionCommitment>,
    /// The event commitment, if available.
    pub event_commitment: Option<EventCommitment>,
    /// The receipt commitment, if available.
    pub receipt_commitment: Option<ReceiptCommitment>,
    /// The length of the state diff, if available.
    pub state_diff_length: Option<usize>,
    /// The number of transactions in this block.
    pub n_transactions: usize,
    /// The number of events in this block.
    pub n_events: usize,
    /// Proposer's oracle-derived recommended L2 gas fee. `None` for pre-V0_14_3 blocks.
    pub fee_proposal_fri: Option<GasPrice>,
```

**File:** crates/apollo_gateway_config/src/config.rs (L289-299)
```rust
impl Default for StatefulTransactionValidatorConfig {
    fn default() -> Self {
        StatefulTransactionValidatorConfig {
            validate_resource_bounds: true,
            max_allowed_nonce_gap: 200,
            reject_future_declare_txs: true,
            max_nonce_for_validation_skip: Nonce(Felt::ONE),
            min_gas_price_percentage: 100,
            versioned_constants_overrides: None,
        }
    }
```

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L86-140)
```rust
pub fn calculate_next_base_gas_price(
    price: GasPrice,
    gas_used: GasAmount,
    gas_target: GasAmount,
    min_gas_price: GasPrice,
) -> GasPrice {
    let versioned_constants = VersionedConstants::latest_constants();
    assert!(
        gas_target < versioned_constants.max_block_size,
        "Gas target must be lower than max block size."
    );
    assert!(gas_target.0 > 0, "Gas target must be greater than zero.");
    assert!(
        versioned_constants.gas_price_max_change_denominator > 0,
        "Denominator constant must be greater than zero."
    );

    // If the current price is below the minimum, apply a gradual adjustment and return early.
    // This allows the price to increase by at most 1/MIN_GAS_PRICE_INCREASE_DENOMINATOR per block.
    if price < min_gas_price {
        let max_increase = price.0 / MIN_GAS_PRICE_INCREASE_DENOMINATOR;
        let adjusted = price.0 + max_increase;
        // Cap at min_gas_price to avoid overshooting
        let adjusted_price = adjusted.min(min_gas_price.0);
        info!(
            "Fee Market: Price {} below minimum gas price {}, adjusted price: {} )",
            price.0, min_gas_price.0, adjusted_price
        );
        return GasPrice(adjusted_price);
    }

    // Use U256 to avoid overflow, as multiplying a u128 by a u64 remains within U256 bounds.
    let gas_delta = U256::from(gas_used.0.abs_diff(gas_target.0));
    let gas_target_u256 = U256::from(gas_target.0);
    let price_u256 = U256::from(price.0);

    // Calculate price change by multiplying first, then dividing. This avoids the precision loss
    // that occurs when dividing before multiplying.
    let denominator =
        gas_target_u256 * U256::from(versioned_constants.gas_price_max_change_denominator);
    let price_change = (price_u256 * gas_delta) / denominator;

    let adjusted_price_u256 =
        if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };

    // Sanity check: ensure direction of change is correct
    assert!(
        gas_used > gas_target && adjusted_price_u256 >= price_u256
            || gas_used <= gas_target && adjusted_price_u256 <= price_u256
    );

    // Price should not realistically exceed u128::MAX, bound to avoid theoretical overflow.
    let adjusted_price = u128::try_from(adjusted_price_u256).unwrap_or(u128::MAX);
    GasPrice(max(adjusted_price, min_gas_price.0))
}
```
