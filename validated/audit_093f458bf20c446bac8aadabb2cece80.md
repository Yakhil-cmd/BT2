### Title
Gateway `validate_resource_bounds` Uses Stale Previous-Block L2 Gas Price, Admitting Transactions That Fail Blockifier Pre-Validation — (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidator::validate_resource_bounds` snapshots the L2 gas price from the **last committed block** and uses it as the admission threshold. The batcher builds the next block with a freshly-computed gas price that can be higher. A transaction whose `max_price_per_unit` sits between the two prices passes every gateway check but is then rejected by `check_fee_bounds` inside the batcher, meaning the gateway admits a transaction it should have rejected.

---

### Finding Description

**Stale snapshot read (gateway side)** [1](#0-0) 

`validate_resource_bounds` calls `gateway_fixed_block_state_reader.get_block_info()` and extracts `strk_gas_prices.l2_gas_price` from the **previous** (already-committed) block. That value is then passed to `validate_tx_l2_gas_price_within_threshold`: [2](#0-1) 

With the production default `min_gas_price_percentage = 100`, the admission condition is simply:

```
tx.l2_gas_price  >=  previous_block_l2_gas_price
``` [3](#0-2) 

**Same stale price used for blockifier gateway-validation**

`run_validate_entry_point` also reads from the same `gateway_fixed_block_state_reader`, so the blockifier's own `check_fee_bounds` inside the gateway also runs against the previous block's price: [4](#0-3) 

**Authoritative check in the batcher uses the current block's price**

When the batcher executes the transaction, `perform_pre_validation_stage` → `check_fee_bounds` compares `resource_bounds.max_price_per_unit` against `block_info.gas_prices` of the **new** block being built: [5](#0-4) 

The new block's gas prices are set by the orchestrator/L1 gas-price oracle and are independent of the previous block's prices. The developers acknowledge the gap with an inline TODO: [6](#0-5) 

**The broken invariant**

The gateway's invariant is: *every transaction admitted to the mempool must satisfy `check_fee_bounds` when the batcher executes it*. Because the gateway snapshots `previous_block_l2_gas_price` while the batcher uses `current_block_l2_gas_price`, any block-to-block price increase breaks this invariant for transactions whose `max_price_per_unit` falls in the interval `[previous_price, current_price)`.

---

### Impact Explanation

This matches **High — Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.**

Concretely:
- Transactions with a gas price that is valid for block *N* but insufficient for block *N+1* are admitted to the mempool.
- The batcher rejects them at `perform_pre_validation_stage` (a hard error, not a revert), so they are never included in a block.
- The user's transaction is silently dropped; the nonce is rolled back inside the batcher's transactional state, but the user receives no on-chain confirmation and must resubmit.
- A sustained gas-price increase allows an attacker to flood the mempool with transactions that will always fail the batcher's price check, wasting mempool capacity and sequencer CPU.

---

### Likelihood Explanation

L2 gas prices are updated every block by the orchestrator. Any upward movement between consecutive blocks — even a single unit — creates the window. The condition is unprivileged: any user can craft a transaction with `max_price_per_unit = previous_block_l2_gas_price` and submit it through the public gateway endpoint.

---

### Recommendation

**Short term:** Replace `previous_block_l2_gas_price` in `validate_resource_bounds` with the *next* block's projected L2 gas price (as the TODO comment already notes). The batcher's orchestrator computes this price before building each block; expose it via the `GatewayFixedBlockStateReader` interface or a dedicated oracle so the gateway can validate against the price that will actually be enforced.

**Long term:** Align the `BlockContext` used in `run_validate_entry_point` with the one the batcher will use for the same block, so that gateway blockifier-validation and batcher execution are guaranteed to apply identical gas prices.

---

### Proof of Concept

```
Previous block (N):   strk l2_gas_price = 100
Next block (N+1):     strk l2_gas_price = 110   (orchestrator raised it)

Attacker submits AllResources invoke tx with:
  l2_gas.max_price_per_unit = 100

Gateway validate_resource_bounds:
  100 >= 100% × 100  →  PASS

Gateway run_validate_entry_point (blockifier, using block N prices):
  check_fee_bounds: 100 >= 100  →  PASS

Tx enters mempool.

Batcher builds block N+1 (l2_gas_price = 110):
  perform_pre_validation_stage → check_fee_bounds:
    100 >= 110  →  FAIL  (MaxGasPriceTooLow)

Tx is dropped; user's transaction is lost.
```

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L359-390)
```rust
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

**File:** crates/blockifier/src/transaction/account_transaction.rs (L418-448)
```rust
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
```
