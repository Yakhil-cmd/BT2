### Title
Gateway Stateful Validator Uses Previous Block's L2 Gas Price Instead of Next Block's Price for Admission Threshold — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` compares a transaction's `max_price_per_unit` against the **previous** (committed) block's L2 gas price, but the transaction will actually be executed in the **next** block whose L2 gas price is computed by the fee-market mechanism. The code itself carries a `TODO` acknowledging the wrong value is used. When the fee market lowers the next block's L2 gas price below the previous block's price, valid transactions are rejected at the gateway. When the fee market raises it, transactions that cannot cover the actual execution price are admitted.

### Finding Description

In `validate_resource_bounds`, the gateway fetches the **previous** block's STRK L2 gas price via `gateway_fixed_block_state_reader.get_block_info()` and passes it as the threshold reference to `validate_tx_l2_gas_price_within_threshold`:

```rust
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
``` [1](#0-0) 

The threshold is then computed as `min_gas_price_percentage% × previous_block_l2_gas_price`:

```rust
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();
if tx_l2_gas_price.0 < threshold {
    return Err(...GAS_PRICE_TOO_LOW...);
}
``` [2](#0-1) 

The **next** block's L2 gas price is a distinct, dynamically computed value produced by the fee-market mechanism (`calculate_next_l2_gas_price_for_fin`) and stored in the orchestrator's `self.l2_gas_price`. It is placed into `ProposalInit::l2_gas_price_fri` and then into the block context used for actual execution: [3](#0-2) [4](#0-3) 

The gateway has no access to this computed next-block price at admission time and silently falls back to the previous block's price — the exact mismatch flagged by the `TODO` comment.

Meanwhile, `run_validate_entry_point` correctly advances the block number with `block_info.block_number.unchecked_next()` but still uses the same previous-block gas prices for the block context, so the blockifier validation also runs against the wrong price: [5](#0-4) 

### Impact Explanation

Two distinct failure modes arise:

1. **Valid transactions rejected (High):** When the fee market decreases the next block's L2 gas price below the previous block's price, a transaction whose `max_price_per_unit` lies between the two prices satisfies the actual execution requirement but fails the gateway's threshold check. The transaction is rejected with `GAS_PRICE_TOO_LOW` even though it would succeed in the next block. This matches: *"Mempool/gateway/RPC admission … rejects valid transactions before sequencing."*

2. **Invalid transactions admitted:** When the fee market increases the next block's L2 gas price above the previous block's price, a transaction whose `max_price_per_unit` lies between the two prices passes the gateway check but will fail `check_fee_bounds` inside `perform_pre_validation_stage` at blockifier execution time. The transaction wastes sequencer resources and the user pays a revert fee. [6](#0-5) 

### Likelihood Explanation

The L2 gas price changes every block via the fee-market algorithm. Any block where the fee market moves the price — which is the normal operating condition — creates the window. No special privileges are required; any user submitting a transaction with `max_price_per_unit` set to the expected next-block price (e.g., obtained from an RPC `estimate_fee` call) can trigger the rejection path. The `TODO` comment in the production source confirms the developers are aware the wrong value is used.

### Recommendation

Expose the computed next-block L2 gas price to the gateway stateful validator. The orchestrator already calculates this value before building each block. One approach is to store it in the committed block header (the `fee_market_info.next_l2_gas_price` field already exists in the blob format) and have `GatewayFixedBlockStateReader::get_block_info` return it as the reference price. The `validate_resource_bounds` function should then use that value instead of `previous_block_l2_gas_price`. [7](#0-6) 

### Proof of Concept

1. Observe the current committed block's L2 gas price: `P_prev`.
2. The fee market computes the next block's L2 gas price `P_next < P_prev` (e.g., due to low gas consumption in the previous block).
3. Submit an invoke transaction with `AllResourceBounds { l2_gas: { max_price_per_unit: P_next } }` — this is the correct price for the next block.
4. The gateway calls `validate_resource_bounds`, computes `threshold = 100% × P_prev = P_prev`, and checks `P_next < P_prev` → **rejects** with `GAS_PRICE_TOO_LOW`.
5. The transaction is a valid transaction that would have been accepted and executed successfully in the next block, but it is rejected at the gateway admission stage.

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L228-241)
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
        }
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L323-330)
```rust
        let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
        block_info.block_number = block_info.block_number.unchecked_next();
        let block_context = BlockContext::new(
            block_info,
            self.chain_info.clone(),
            versioned_constants,
            BouncerConfig::max(),
        );
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L367-383)
```rust
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
```

**File:** crates/apollo_consensus_orchestrator/src/build_proposal.rs (L177-188)
```rust
        l2_gas_price_fri: args.l2_gas_price,
        l1_gas_price_wei: l1_prices_wei.l1_gas_price,
        l1_data_gas_price_wei: l1_prices_wei.l1_data_gas_price,
        l1_gas_price_fri: l1_prices_fri.l1_gas_price,
        l1_data_gas_price_fri: l1_prices_fri.l1_data_gas_price,
        starknet_version: starknet_api::block::StarknetVersion::LATEST,
        // TODO(Asmaa): Put the real value once we have it.
        // Sentinel until then; see `expected_version_constant_commitment` for why this is the
        // single source of truth shared with the validator.
        version_constant_commitment: expected_version_constant_commitment(),
        fee_proposal_fri: Some(args.fee_proposal),
    };
```

**File:** crates/apollo_consensus_orchestrator/src/utils.rs (L317-338)
```rust
    let l2_gas_price_fri = NonzeroGasPrice::new(init.l2_gas_price_fri)?;
    let proposal_init_info = PreviousProposalInitInfo::from(init);
    let eth_to_fri_rate = calculate_eth_to_fri_rate(&proposal_init_info)?;

    let l2_gas_price_wei = NonzeroGasPrice::new(init.l2_gas_price_fri.fri_to_wei(eth_to_fri_rate)?)
        .inspect_err(|_| {
            warn!(
                "L2 gas price in wei is zero! Conversion rate: {eth_to_fri_rate}, L2 gas price in \
                 FRI: {}",
                init.l2_gas_price_fri
            )
        })?;
    Ok(starknet_api::block::BlockInfo {
        block_number: init.height,
        block_timestamp: BlockTimestamp(init.timestamp),
        sequencer_address: init.builder,
        gas_prices: GasPrices {
            strk_gas_prices: GasPriceVector {
                l1_gas_price: l1_gas_price_fri,
                l1_data_gas_price: l1_data_gas_price_fri,
                l2_gas_price: l2_gas_price_fri,
            },
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L374-396)
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
```

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L425-441)
```rust
    /// Returns the next L2 gas price without mutating context. Used when building the fin and when
    /// updating at decision time.
    fn calculate_next_l2_gas_price(&self, height: BlockNumber, l2_gas_used: GasAmount) -> GasPrice {
        let fee_actual = compute_fee_actual(
            &self.fee_proposals_window,
            height,
            VersionedConstants::latest_constants().fee_proposal_window_size,
        );
        calculate_next_l2_gas_price_for_fin(
            self.l2_gas_price,
            height,
            l2_gas_used,
            self.config.dynamic_config.override_l2_gas_price_fri,
            &self.config.dynamic_config.min_l2_gas_price_per_height,
            fee_actual,
        )
    }
```
