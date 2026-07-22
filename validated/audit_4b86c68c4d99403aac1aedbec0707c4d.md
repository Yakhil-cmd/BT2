### Title
Gateway stateful validator uses stale `l2_gas_price` instead of `next_l2_gas_price` for resource-bounds threshold, admitting transactions that fail at execution and rejecting transactions that would succeed - (`crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

`StatefulTransactionValidator::validate_resource_bounds` computes its admission threshold from the previous block's `l2_gas_price` field. The next block executes at `next_l2_gas_price` — a distinct field in `BlockHeaderWithoutHash` computed via the EIP-1559 mechanism from the previous block's gas consumption. With `min_gas_price_percentage = 100` (the production default), the gateway admits every transaction whose `max_price_per_unit` is ≥ the previous block's gas price, even when that price is below the next block's actual execution price. Those transactions then fail at the blockifier's `check_fee_bounds` inside the batcher. Conversely, when gas price is falling, valid transactions are rejected at the gateway.

---

### Finding Description

In `validate_resource_bounds`, the code reads `gas_prices.strk_gas_prices.l2_gas_price` from `get_block_info()`:

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

`gas_prices.strk_gas_prices.l2_gas_price` is the gas price that was used for transactions **in the previous block**. The next block will execute at `next_l2_gas_price`, a separate field in `BlockHeaderWithoutHash`: [2](#0-1) 

`next_l2_gas_price` is stored in the block header and propagated through storage: [3](#0-2) 

The two values are distinct: `l2_gas_price` is the price that applied to the block just committed; `next_l2_gas_price` is the EIP-1559-adjusted price for the **next** block, computed from that block's gas consumption. The developer explicitly acknowledged the wrong field is being used: `// TODO(Arni): getnext_l2_gas_price from the block header.`

The threshold computation is:

```rust
let threshold = (gas_price_threshold_multiplier * previous_block_l2_gas_price.get().0).to_integer();
if tx_l2_gas_price.0 < threshold { return Err(...); }
``` [4](#0-3) 

With `min_gas_price_percentage = 100` (production default in both `gateway_config.json` and `StatefulTransactionValidatorConfig::default()`): [5](#0-4) [6](#0-5) 

the threshold equals `previous_block_l2_gas_price` exactly. Any transaction with `max_price_per_unit` in the range `[previous_block_l2_gas_price, next_l2_gas_price)` passes the gateway check but fails at the blockifier's `check_fee_bounds`:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [7](#0-6) 

which is called from `perform_pre_validation_stage` inside the batcher: [8](#0-7) 

The batcher builds the next block using `next_l2_gas_price` from the previous block's header (via the consensus orchestrator's `l2_gas_price` field, which is initialized from `next_l2_gas_price`): [9](#0-8) 

The gateway's `run_validate_entry_point` also uses the previous block's `BlockInfo` (with only the block number incremented), so the blockifier validation inside the gateway is also wrong — it uses the same stale `l2_gas_price` rather than `next_l2_gas_price`: [10](#0-9) 

---

### Impact Explanation

**Matching impact**: *High. Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing.*

- **Gas price rising** (high network usage): `next_l2_gas_price > l2_gas_price`. The gateway admits transactions with `max_price_per_unit ∈ [l2_gas_price, next_l2_gas_price)`. These transactions enter the mempool and are pulled by the batcher, but fail at `check_fee_bounds` because `max_price_per_unit < next_l2_gas_price`. Invalid transactions are admitted.

- **Gas price falling** (low network usage): `next_l2_gas_price < l2_gas_price`. The gateway rejects transactions with `max_price_per_unit ∈ [next_l2_gas_price, l2_gas_price)`. These transactions would succeed at the batcher because `max_price_per_unit ≥ next_l2_gas_price`. Valid transactions are rejected.

---

### Likelihood Explanation

The EIP-1559 mechanism adjusts `next_l2_gas_price` every block based on gas consumption relative to the target. During any period of sustained high or low usage, `next_l2_gas_price` diverges from `l2_gas_price`. With `min_gas_price_percentage = 100` in production, the full divergence is exposed with no buffer. Any unprivileged user can trigger the admission path by submitting a V3 (`AllResources`) invoke transaction.

---

### Recommendation

Replace the read of `gas_prices.strk_gas_prices.l2_gas_price` with `next_l2_gas_price` from the block header (`BlockHeaderWithoutHash.next_l2_gas_price`). This requires `GatewayFixedBlockStateReader::get_block_info` to either return the full `BlockHeaderWithoutHash` or expose a dedicated `get_next_l2_gas_price` method backed by the stored header field (`StorageBlockHeader.next_l2_gas_price`). [11](#0-10) 

---

### Proof of Concept

1. Observe that the latest committed block has `l2_gas_price = 100 fri` and `next_l2_gas_price = 120 fri` (due to high gas consumption in that block — a normal EIP-1559 increase).
2. Submit an invoke V3 transaction with `l2_gas.max_price_per_unit = 100 fri`.
3. `validate_resource_bounds` computes threshold = 100% × 100 = 100 fri; admits the transaction (100 ≥ 100). [12](#0-11) 
4. Transaction passes all gateway checks and enters the mempool.
5. Batcher pulls the transaction and builds the next block with gas price = 120 fri (from `next_l2_gas_price`).
6. Blockifier's `check_fee_bounds` evaluates `100 < 120` → `MaxGasPriceTooLow` → transaction reverts or is rejected. [7](#0-6) 
7. The transaction consumed mempool and batcher resources despite being invalid for the block it was admitted into.

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

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L322-330)
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

**File:** crates/starknet_api/src/block.rs (L232-248)
```rust
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

**File:** crates/apollo_storage/src/header.rs (L85-90)
```rust
    pub l2_gas_price: GasPricePerToken,
    /// The amount of L2 gas consumed.
    pub l2_gas_consumed: GasAmount,
    /// The next L2 gas price.
    pub next_l2_gas_price: GasPrice,
    /// The state root after this block.
```

**File:** crates/apollo_storage/src/header.rs (L208-240)
```rust
    fn get_block_header(&self, block_number: BlockNumber) -> StorageResult<Option<BlockHeader>> {
        let Some(block_header) = self.get_storage_block_header(&block_number)? else {
            return Ok(None);
        };
        let Some(starknet_version) = self.get_starknet_version(block_number)? else {
            return Ok(None);
        };
        Ok(Some(BlockHeader {
            block_hash: block_header.block_hash,
            block_header_without_hash: BlockHeaderWithoutHash {
                parent_hash: block_header.parent_hash,
                block_number: block_header.block_number,
                l1_gas_price: block_header.l1_gas_price,
                l1_data_gas_price: block_header.l1_data_gas_price,
                l2_gas_price: block_header.l2_gas_price,
                l2_gas_consumed: block_header.l2_gas_consumed,
                next_l2_gas_price: block_header.next_l2_gas_price,
                state_root: block_header.state_root,
                sequencer: block_header.sequencer,
                timestamp: block_header.timestamp,
                l1_da_mode: block_header.l1_da_mode,
                starknet_version,
                fee_proposal_fri: block_header.fee_proposal_fri,
            },
            state_diff_commitment: block_header.state_diff_commitment,
            transaction_commitment: block_header.transaction_commitment,
            event_commitment: block_header.event_commitment,
            receipt_commitment: block_header.receipt_commitment,
            state_diff_length: block_header.state_diff_length,
            n_transactions: block_header.n_transactions,
            n_events: block_header.n_events,
        }))
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

**File:** crates/apollo_deployments/resources/app_configs/gateway_config.json (L19-19)
```json
  "gateway_config.static_config.stateful_tx_validator_config.min_gas_price_percentage": 100,
```

**File:** crates/blockifier/src/transaction/account_transaction.rs (L355-372)
```rust
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

**File:** crates/apollo_consensus_orchestrator/src/sequencer_consensus_context.rs (L427-441)
```rust
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
