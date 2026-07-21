### Title
Gateway `validate_resource_bounds` Uses Current Block's `l2_gas_price.price_in_fri` Instead of `next_l2_gas_price` as Admission Threshold — (`crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs`)

---

### Summary

`get_block_info_from_sync_client` populates `strk_gas_prices.l2_gas_price` from `block_header.l2_gas_price.price_in_fri` (the price that was used *in* the previous block), not from `block_header.next_l2_gas_price` (the fee-market-derived price for the *next* block). `validate_resource_bounds` then compares the transaction's `max_price_per_unit` against this wrong reference, corrupting the admission decision. The code itself contains an explicit TODO acknowledging the bug.

---

### Finding Description

`BlockHeaderWithoutHash` carries two semantically distinct L2 gas price fields:

- `l2_gas_price: GasPricePerToken` — the price that was applied *inside* the previous block.
- `next_l2_gas_price: GasPrice` — the EIP-1559-style fee-market price computed from `l2_gas_consumed` in that block, which is the price that *will* apply to the next block. [1](#0-0) 

`get_block_info_from_sync_client` builds the `BlockInfo` returned to the validator and maps `strk_gas_prices.l2_gas_price` from `block_header.l2_gas_price.price_in_fri`: [2](#0-1) 

`next_l2_gas_price` is a separate field on the same struct and is never read here.

`validate_resource_bounds` then fetches this `BlockInfo` and uses `strk_gas_prices.l2_gas_price` as the threshold reference. The code even contains a developer TODO acknowledging the wrong field is being used: [3](#0-2) 

The threshold is then applied via `validate_tx_l2_gas_price_within_threshold` using `min_gas_price_percentage` (default 100 %) of this wrong price. [4](#0-3) 

---

### Impact Explanation

Because `l2_gas_price.price_in_fri` and `next_l2_gas_price` diverge whenever the fee market is adjusting:

**Case 1 — price rising** (`next_l2_gas_price > l2_gas_price.price_in_fri`):  
A transaction with `max_price_per_unit` in the range `[l2_gas_price.price_in_fri × threshold, next_l2_gas_price × threshold)` passes the gateway check but will fail blockifier's `check_fee_bounds` during execution because the actual block price is `next_l2_gas_price`. The gateway admits an invalid transaction.

**Case 2 — price falling** (`next_l2_gas_price < l2_gas_price.price_in_fri`):  
A transaction with `max_price_per_unit` in the range `[next_l2_gas_price × threshold, l2_gas_price.price_in_fri × threshold)` is rejected by the gateway even though it can pay the actual next-block price. A valid transaction is incorrectly rejected.

Both cases match the defined High impact: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

---

### Likelihood Explanation

The fee market adjusts `next_l2_gas_price` every block based on `l2_gas_consumed`. During any period of sustained load or sustained low activity the two prices diverge by up to the per-block adjustment cap. No privileged access is required; any user can observe both prices on-chain and craft a transaction whose `max_price_per_unit` falls in the gap. The TODO comment confirms the developers are aware the wrong field is used.

---

### Recommendation

In `get_block_info_from_sync_client`, replace `block_header.l2_gas_price.price_in_fri` with `block_header.next_l2_gas_price` when populating `strk_gas_prices.l2_gas_price`:

```rust
strk_gas_prices: GasPriceVector {
    l1_gas_price: block_header.l1_gas_price.price_in_fri.try_into()?,
    l1_data_gas_price: block_header.l1_data_gas_price.price_in_fri.try_into()?,
    // Fix: use next_l2_gas_price, not l2_gas_price.price_in_fri
    l2_gas_price: block_header.next_l2_gas_price.try_into()?,
},
```

This resolves the TODO in `validate_resource_bounds` and aligns the admission threshold with the price that will actually be enforced during blockifier execution.

---

### Proof of Concept

The existing test in `sync_state_reader_test.rs` already demonstrates the wrong mapping — it asserts `strk_gas_prices.l2_gas_price == l2_gas_price.price_in_fri` and never checks `next_l2_gas_price`: [5](#0-4) 

A concrete demonstration:

1. Construct a `SyncBlock` where `l2_gas_price.price_in_fri = 100` and `next_l2_gas_price = 200` (price doubling after a heavily-loaded block).
2. Call `get_block_info()` — the returned `strk_gas_prices.l2_gas_price` is `100`, not `200`.
3. Submit a transaction with `max_price_per_unit = 150` (above the wrong threshold of 100, below the correct threshold of 200).
4. `validate_resource_bounds` passes (150 ≥ 100 × 100 %).
5. The blockifier's `check_fee_bounds` rejects the transaction because 150 < 200.

The gateway has admitted a transaction that cannot be included in any block.

### Citations

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

**File:** crates/apollo_gateway/src/gateway_fixed_block_state_reader.rs (L46-50)
```rust
                strk_gas_prices: GasPriceVector {
                    l1_gas_price: block_header.l1_gas_price.price_in_fri.try_into()?,
                    l1_data_gas_price: block_header.l1_data_gas_price.price_in_fri.try_into()?,
                    l2_gas_price: block_header.l2_gas_price.price_in_fri.try_into()?,
                },
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator.rs (L229-241)
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
        }
```

**File:** crates/apollo_gateway/src/sync_state_reader_test.rs (L56-111)
```rust
    let l2_gas_price = GasPricePerToken { price_in_wei: 8_u8.into(), price_in_fri: 9_u8.into() };
    let l1_da_mode = L1DataAvailabilityMode::get_test_instance(&mut get_rng());
    let starknet_version = StarknetVersion::LATEST;

    mock_state_sync_client.expect_get_block().times(1).with(predicate::eq(block_number)).returning(
        move |_| {
            Ok(SyncBlock {
                state_diff: Default::default(),
                account_transaction_hashes: Default::default(),
                l1_transaction_hashes: Default::default(),
                block_header_without_hash: BlockHeaderWithoutHash {
                    block_number,
                    l1_gas_price,
                    l1_data_gas_price,
                    l2_gas_price,
                    sequencer: SequencerContractAddress(sequencer_address),
                    timestamp: block_timestamp,
                    l1_da_mode,
                    starknet_version,
                    ..Default::default()
                },
                block_header_commitments: Some(Default::default()),
            })
        },
    );

    let gateway_fixed_block_sync_state_client =
        GatewayFixedBlockSyncStateClient::new(Arc::new(mock_state_sync_client), block_number);
    let result = gateway_fixed_block_sync_state_client.get_block_info().await.unwrap();

    assert_eq!(
        result,
        BlockInfo {
            block_number,
            block_timestamp,
            sequencer_address,
            gas_prices: GasPrices {
                eth_gas_prices: GasPriceVector {
                    l1_gas_price: NonzeroGasPrice::new_unchecked(l1_gas_price.price_in_wei),
                    l1_data_gas_price: NonzeroGasPrice::new_unchecked(
                        l1_data_gas_price.price_in_wei
                    ),
                    l2_gas_price: NonzeroGasPrice::new_unchecked(l2_gas_price.price_in_wei),
                },
                strk_gas_prices: GasPriceVector {
                    l1_gas_price: NonzeroGasPrice::new_unchecked(l1_gas_price.price_in_fri),
                    l1_data_gas_price: NonzeroGasPrice::new_unchecked(
                        l1_data_gas_price.price_in_fri
                    ),
                    l2_gas_price: NonzeroGasPrice::new_unchecked(l2_gas_price.price_in_fri),
                },
            },
            use_kzg_da: l1_da_mode.is_use_kzg_da(),
            starknet_version: Default::default(),
        }
    );
```
