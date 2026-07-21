### Title
Gateway L2 Gas Price Admission Check Uses Stale `l2_gas_price` Instead of `next_l2_gas_price`, Admitting Transactions That Fail During Execution - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

`StatefulTransactionValidator::validate_resource_bounds` checks a transaction's `max_price_per_unit` against the **current block's** `l2_gas_price`, but the batcher executes the transaction in the **next block** whose L2 gas price is `next_l2_gas_price` — a distinct EIP-1559-derived value stored separately in the block header. When the network is under load and `next_l2_gas_price > l2_gas_price`, the gateway admits transactions whose `max_price_per_unit` satisfies the gateway threshold but is below the actual execution price, causing them to fail with `MaxGasPriceTooLow` inside the batcher. The code itself acknowledges the bug with a TODO comment at the exact line.

### Finding Description

`validate_resource_bounds` in `StatefulTransactionValidator` calls `get_block_info()` and reads `gas_prices.strk_gas_prices.l2_gas_price`:

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

`GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` populates that field from `block_header.l2_gas_price.price_in_fri` — the **current** block's L2 gas price — and never reads `block_header.next_l2_gas_price`:

```rust
strk_gas_prices: GasPriceVector {
    ...
    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
},
``` [2](#0-1) 

The block header carries both fields as separate values:

```rust
pub l2_gas_price: GasPricePerToken,   // price used in THIS block
pub next_l2_gas_price: GasPrice,      // EIP-1559 price for the NEXT block
``` [3](#0-2) 

The same stale price is also used when `run_validate_entry_point` builds the `BlockContext` for blockifier validation at the gateway — it calls `get_block_info()` and only bumps the block number, leaving gas prices unchanged:

```rust
let mut block_info = self.gateway_fixed_block_state_reader.get_block_info().await?;
block_info.block_number = block_info.block_number.unchecked_next();
let block_context = BlockContext::new(block_info, ...);
``` [4](#0-3) 

So `check_fee_bounds` inside `perform_pre_validation_stage` also compares `max_price_per_unit` against `l2_gas_price`, not `next_l2_gas_price`:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [5](#0-4) 

In the batcher, `SequencerConsensusContext::update_l2_gas_price` computes the next block's price via EIP-1559 and stores it in `self.l2_gas_price`, which is then used as the actual L2 gas price for block execution:

```rust
fn update_l2_gas_price(&mut self, height: BlockNumber, l2_gas_used: GasAmount) {
    self.l2_gas_price = self.calculate_next_l2_gas_price(height, l2_gas_used);
``` [6](#0-5) 

The EIP-1559 formula can raise the price by up to `price * gas_delta / (gas_target * denominator)` per block:

```rust
let price_change = (price_u256 * gas_delta) / denominator;
let adjusted_price_u256 =
    if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };
``` [7](#0-6) 

The result: a transaction whose `max_price_per_unit` equals `l2_gas_price` (the gateway's threshold with `min_gas_price_percentage = 100`, the default) passes every gateway check but is rejected by `check_fee_bounds` in the batcher when `next_l2_gas_price > l2_gas_price`.

### Impact Explanation

The gateway admits transactions into the mempool that will deterministically fail during block execution with `MaxGasPriceTooLow`. This matches the allowed impact: **"High. Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."** Users who set `max_price_per_unit` to exactly the gateway-advertised minimum lose fees on reverted transactions. Under sustained load the discrepancy is permanent and systematic, not transient.

### Likelihood Explanation

The L2 gas price rises whenever `gas_used > gas_target` — a routine condition on a busy network. The default `min_gas_price_percentage` is 100, meaning the gateway threshold equals `l2_gas_price` exactly. Any transaction submitted at that minimum during a rising-price period is affected. The developers already identified the root cause (the TODO comment at line 229) but have not yet applied the fix.

### Recommendation

1. Extend `GatewayFixedBlockSyncStateClient::get_block_info_from_sync_client` (or add a dedicated accessor) to expose `block_header.next_l2_gas_price`.
2. Replace the `l2_gas_price` read in `validate_resource_bounds` with `next_l2_gas_price`.
3. In `run_validate_entry_point`, populate the `BlockContext`'s L2 gas price from `next_l2_gas_price` rather than from the current block's `l2_gas_price`, so that `check_fee_bounds` inside blockifier validation uses the same price the batcher will use.

### Proof of Concept

```
Block N committed:
  l2_gas_price        = 100 FRI   (stored in block header, read by gateway)
  next_l2_gas_price   = 112 FRI   (EIP-1559 result of a heavily-loaded block N)

User submits Invoke V3 with max_price_per_unit = 100 FRI.

Gateway validate_resource_bounds:
  threshold = 100% * 100 = 100 FRI
  100 >= 100  → PASS

Gateway run_validate_entry_point (blockifier check_fee_bounds):
  block_context.l2_gas_price = 100 FRI  (stale, from get_block_info())
  100 >= 100  → PASS

Transaction enters mempool.

Batcher builds block N+1:
  block_context.l2_gas_price = 112 FRI  (from next_l2_gas_price of block N)
  check_fee_bounds: 100 < 112  → FAIL MaxGasPriceTooLow

Transaction reverts; user pays fees for a failed transaction.
```

### Citations

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L227-241)
```rust
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

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L46-50)
```rust
                strk_gas_prices: GasPriceVector {
                    l1_gas_price: block_header.l1_gas_price.price_in_fri.try_into()?,
                    l1_data_gas_price: block_header.l1_data_gas_price.price_in_fri.try_into()?,
                    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
                },
```

**File:** crates/apollo_storage/src/header.rs (L85-89)
```rust
    pub l2_gas_price: GasPricePerToken,
    /// The amount of L2 gas consumed.
    pub l2_gas_consumed: GasAmount,
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L441-449)
```rust
                            if resource_bounds.max_price_per_unit < actual_gas_price.get() {
                                insufficiencies_resource.push(
                                    ResourceBoundsError::MaxGasPriceTooLow {
                                        resource: *resource,
                                        max_gas_price: resource_bounds.max_price_per_unit,
                                        actual_gas_price: (*actual_gas_price).into(),
                                    },
                                );
                            }
```

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L496-499)
```rust
    fn update_l2_gas_price(&mut self, height: BlockNumber, l2_gas_used: GasAmount) {
        self.l2_gas_price = self.calculate_next_l2_gas_price(height, l2_gas_used);
        let gas_price_u64 = u64::try_from(self.l2_gas_price.0).unwrap_or(u64::MAX);
        CONSENSUS_L2_GAS_PRICE.set_lossy(gas_price_u64);
```

**File:** crates/apollo_consensus_orchestrator/src/fee_market/mod.rs (L126-129)
```rust
    let price_change = (price_u256 * gas_delta) / denominator;

    let adjusted_price_u256 =
        if gas_used > gas_target { price_u256 + price_change } else { price_u256 - price_change };
```
