### Title
Gateway L2 Gas Price Threshold Uses Stale `l2_gas_price` Instead of `next_l2_gas_price`, Causing Incorrect Admission Decisions - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The gateway's stateful `validate_resource_bounds` check compares a transaction's `max_l2_gas_price` against the **current block's** `l2_gas_price` (the price that was used for transactions already in the committed block), rather than `next_l2_gas_price` (the EIP-1559-derived price that will actually be enforced when the transaction executes in the **next** block). This is the direct Sequencer analog of the Chainlink `latestRoundData` staleness bug: a stale price value is used for a critical admission gate, causing the gateway to accept transactions that the blockifier will reject, or reject transactions the blockifier would accept.

### Finding Description

In `StatefulTransactionValidator::validate_resource_bounds`, the reference price is fetched as:

```rust
// TODO(Arni): getnext_l2_gas_price from the block header.
let previous_block_l2_gas_price = self
    .gateway_fixed_block_state_reader
    .get_block_info()
    .await?
    .gas_prices
    .strk_gas_prices
    .l2_gas_price;
``` [1](#0-0) 

`get_block_info()` is implemented in `GatewayFixedBlockSyncStateClient` and maps `block_header.l2_gas_price.price_in_fri` into `strk_gas_prices.l2_gas_price`: [2](#0-1) 

The `BlockHeaderWithoutHash` struct carries **two distinct** L2 gas price fields:

- `l2_gas_price: GasPricePerToken` — the price used for transactions **inside** the committed block.
- `next_l2_gas_price: GasPrice` — the EIP-1559-adjusted price that will be enforced for transactions in the **next** block. [3](#0-2) 

`get_block_info_from_sync_client` reads `l2_gas_price` but **never reads `next_l2_gas_price`**, so the `BlockInfo` returned to the gateway contains the stale price. The TODO comment in the production code explicitly acknowledges this:

> `// TODO(Arni): getnext_l2_gas_price from the block header.`

The `next_l2_gas_price` is computed by the EIP-1559 formula in `calculate_next_base_gas_price` and stored in the block header: [4](#0-3) 

When the batcher executes the transaction, `AccountTransaction::perform_pre_validation_stage` calls `check_fee_bounds`, which compares the transaction's `max_price_per_unit` against the **actual block's** gas price — which is `next_l2_gas_price`: [5](#0-4) [6](#0-5) 

### Impact Explanation

**Scenario A — Price rising (normal EIP-1559 congestion):**

Let `P_current = l2_gas_price` of the latest committed block, and `P_next = next_l2_gas_price` (higher, because the block was above the gas target). A user submits a transaction with `max_l2_gas_price = X` where `P_current ≤ X < P_next`.

1. Gateway threshold = `min_gas_price_percentage% × P_current`. Since `X ≥ P_current`, the transaction **passes** gateway admission.
2. Transaction enters the mempool.
3. Batcher builds the next block with gas price `P_next`. Blockifier's `check_fee_bounds` sees `X < P_next` and **rejects** the transaction with `MaxGasPriceTooLow`.

Result: gateway admitted a transaction that the blockifier will always reject — wasted mempool slot, failed execution, user confusion, and potential DoS amplification.

**Scenario B — Price falling:**

`P_next < P_current`. A user submits `X` where `P_next ≤ X < P_current`. Gateway threshold = `min_gas_price_percentage% × P_current > X`, so the transaction is **rejected** by the gateway even though the blockifier would accept it at `P_next`.

Result: valid transactions are incorrectly rejected at the gateway.

Both scenarios match the allowed impact: **"High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."**

### Likelihood Explanation

The L2 gas price changes every block via the EIP-1559 formula whenever gas usage deviates from the target. This is the normal operating condition of the fee market. Any block with above- or below-target gas usage produces a `next_l2_gas_price ≠ l2_gas_price`, making the discrepancy permanent and continuous. No special attacker capability is required — any unprivileged user submitting a transaction with a price in the gap between the two values triggers the incorrect admission decision.

### Recommendation

In `validate_resource_bounds`, replace the read of `block_header.l2_gas_price.price_in_fri` with `block_header.next_l2_gas_price`. Concretely:

1. Extend `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` (or add a separate accessor) to expose `block_header_without_hash.next_l2_gas_price`.
2. In `validate_resource_bounds`, use `next_l2_gas_price` as the reference price passed to `validate_tx_l2_gas_price_within_threshold`.

This resolves the TODO comment and aligns the gateway admission threshold with the price the blockifier will actually enforce.

### Proof of Concept

1. Observe the latest committed block header: `l2_gas_price.price_in_fri = P`, `next_l2_gas_price = P_next > P` (block was above gas target).
2. Submit an invoke transaction V3 with `AllResourceBounds { l2_gas: { max_price_per_unit: P, ... }, ... }` (i.e., `max_l2_gas_price = P`).
3. Gateway `validate_resource_bounds` computes threshold = `min_gas_price_percentage% × P`. With default `min_gas_price_percentage = 100`, threshold = `P`. Since `P ≥ P`, the check passes and the transaction is admitted.
4. The batcher builds the next block with `l2_gas_price = P_next`. `AccountTransaction::check_fee_bounds` evaluates `max_price_per_unit (P) < actual_gas_price (P_next)` → `ResourceBoundsError::MaxGasPriceTooLow` → transaction is rejected at execution.
5. The gateway has admitted a transaction that will always fail, confirming the broken admission invariant. [7](#0-6) [8](#0-7)

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L228-240)
```rust
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
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L358-390)
```rust
    // TODO(Arni): Consider running this validation for all gas prices.
    fn validate_tx_l2_gas_price_within_threshold(
        &self,
        tx_resource_bounds: ValidResourceBounds,
        previous_block_l2_gas_price: NonzeroGasPrice,
    ) -> StatefulTransactionValidatorResult<()> {
        match tx_resource_bounds {
            ValidResourceBounds::AllResources(tx_resource_bounds) => {
                let tx_l2_gas_price = tx_resource_bounds.l2_gas.max_price_per_unit;
                let gas_price_threshold_multiplier =
                    Ratio::new(self.config.min_gas_price_percentage.into(), 100_u128);
                let threshold = (gas_price_threshold_multiplier
                    * previous_block_l2_gas_price.get().0)
                    .to_integer();
                if tx_l2_gas_price.0 < threshold {
                    return Err(StarknetError {
                        // We didn't have this kind of an error.
                        code: StarknetErrorCode::UnknownErrorCode(
                            "StarknetErrorCode.GAS_PRICE_TOO_LOW".to_string(),
                        ),
                        message: format!(
                            "Transaction L2 gas price {tx_l2_gas_price} is below the required \
                             threshold {threshold}.",
                        ),
                    });
                }
            }
            ValidResourceBounds::L1Gas(_) => {
                // No validation required for legacy transactions.
            }
        }
        Ok(())
    }
```

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L30-57)
```rust
    async fn get_block_info_from_sync_client(&self) -> StarknetResult<BlockInfo> {
        let block = self.state_sync_client.get_block(self.block_number).await.map_err(|e| {
            StarknetError::internal_with_logging("Failed to get latest block info", e)
        })?;

        let block_header = block.block_header_without_hash;
        let block_info = BlockInfo {
            block_number: block_header.block_number,
            block_timestamp: block_header.timestamp,
            sequencer_address: block_header.sequencer.0,
            gas_prices: GasPrices {
                eth_gas_prices: GasPriceVector {
                    l1_gas_price: block_header.l1_gas_price.price_in_wei.try_into()?,
                    l1_data_gas_price: block_header.l1_data_gas_price.price_in_wei.try_into()?,
                    l2_gas_price: block_header.l2_gas_price.price_in_wei.try_into()?,
                },
                strk_gas_prices: GasPriceVector {
                    l1_gas_price: block_header.l1_gas_price.price_in_fri.try_into()?,
                    l1_data_gas_price: block_header.l1_data_gas_price.price_in_fri.try_into()?,
                    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
                },
            },
            use_kzg_da: block_header.l1_da_mode.is_use_kzg_da(),
            starknet_version: block_header.starknet_version,
        };

        Ok(block_info)
    }
```

**File:** crates/starknet_api/src/block.rs (L231-248)
```rust
#[derive(Debug, Default, Clone, Eq, PartialEq, Hash, Deserialize, Serialize, PartialOrd, Ord)]
pub struct BlockHeaderWithoutHash {
    pub parent_hash: BlockHash,
    pub block_number: BlockNumber,
    pub l1_gas_price: GasPricePerToken,
    pub l1_data_gas_price: GasPricePerToken,
    pub l2_gas_price: GasPricePerToken,
    pub l2_gas_consumed: GasAmount,
    pub next_l2_gas_price: GasPrice,
    pub state_root: GlobalRoot,
    pub sequencer: SequencerContractAddress,
    pub timestamp: BlockTimestamp,
    pub l1_da_mode: L1DataAvailabilityMode,
    pub starknet_version: StarknetVersion,
    // TODO(AndrewL): Add this field into the block hash.
    /// Proposer's oracle-derived recommended L2 gas fee. `None` for pre-V0_14_3 blocks.
    pub fee_proposal_fri: Option<GasPrice>,
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L353-372)
```rust
    // Performs static checks before executing validation entry point.
    // Note that nonce is incremented during these checks.
    pub fn perform_pre_validation_stage<S: State + StateReader>(
        &self,
        state: &mut S,
        tx_context: &TransactionContext,
    ) -> TransactionPreValidationResult<()> {
        let tx_info = &tx_context.tx_info;
        Self::handle_nonce(state, tx_info, self.execution_flags.strict_nonce_check)?;

        if self.execution_flags.charge_fee {
            self.check_fee_bounds(tx_context)?;

            verify_can_pay_committed_bounds(state, tx_context).map_err(Box::new)?;
        }

        self.validate_proof_facts(&tx_context.block_context, state)?;

        Ok(())
    }
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L398-458)
```rust
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
