### Title
Gateway L2 Gas Price Admission Threshold Truncates to Zero via `to_integer()` Floor Division, Bypassing Minimum Price Check — (`File: crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

`validate_tx_l2_gas_price_within_threshold` computes the minimum acceptable L2 gas price as `floor(min_gas_price_percentage / 100 × previous_block_l2_gas_price)` using `Ratio::to_integer()`, which performs floor (truncating) division. When the product is a non-integer less than 1 — specifically when `min_gas_price_percentage × previous_block_l2_gas_price < 100` — the threshold silently collapses to `0`. Because `GasPrice` is a `u128`, the subsequent guard `tx_l2_gas_price.0 < 0` is vacuously false, and every transaction, including those with `max_price_per_unit = 0`, passes the stateful gateway admission check.

### Finding Description

In `validate_tx_l2_gas_price_within_threshold`:

```rust
let gas_price_threshold_multiplier =
    Ratio::new(self.config.min_gas_price_percentage.into(), 100_u128);
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();          // ← floor division
if tx_l2_gas_price.0 < threshold {
    return Err(...);
}
```

`Ratio::to_integer()` from `num-rational` returns the integer part of the rational number, i.e., `⌊numerator / denominator⌋`. When `min_gas_price_percentage = 80` and `previous_block_l2_gas_price = 1` FRI/gas:

```
threshold = ⌊(80/100) × 1⌋ = ⌊0.8⌋ = 0
```

The comparison `tx_l2_gas_price.0 < 0` is always `false` for `u128`, so the entire dynamic minimum-price guard is eliminated. The correct behavior would be to round the threshold **up** (ceiling), so that a fractional threshold of 0.8 becomes 1, preserving the intent that the transaction must offer at least some non-zero price.

The condition that triggers the collapse is:

```
min_gas_price_percentage × previous_block_l2_gas_price < 100
```

For the documented example value of `min_gas_price_percentage = 80`, this triggers whenever `previous_block_l2_gas_price ≤ 1`. For `min_gas_price_percentage = 50` it triggers for `previous_block_l2_gas_price ≤ 1`. For `min_gas_price_percentage = 9` it triggers for `previous_block_l2_gas_price ≤ 11`. [1](#0-0) 

The config field is typed `u8` and the documentation explicitly gives `80` as an example non-100 value, confirming that sub-100 percentages are an intended operational mode: [2](#0-1) 

### Impact Explanation

When the threshold collapses to zero, the stateful gateway's dynamic L2 gas price admission check is completely bypassed. Any `AllResources` V3 transaction — regardless of its `l2_gas.max_price_per_unit` — passes `validate_resource_bounds` and proceeds to mempool admission. This allows an attacker to flood the mempool with zero-price or near-zero-price transactions during any period when the previous block's L2 gas price is small (e.g., network bootstrap, testnet, or after a sustained low-congestion period that drives the EIP-1559 price toward its minimum). These transactions will later fail blockifier pre-validation (`check_fee_bounds`) but only after consuming mempool capacity and sequencer validation resources.

This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions … before sequencing."* [3](#0-2) 

### Likelihood Explanation

In production today, the L2 gas price is in the range of tens of billions of FRI/gas, so for typical `min_gas_price_percentage` values (50–99) the threshold is far above zero and the bug does not trigger. However:

1. The config is operator-controlled and the documentation explicitly encourages values below 100.
2. During network bootstrap, the EIP-1559 price starts at `min_gas_price` (which can be as low as 1 FRI/gas per `VersionedConstants`).
3. On testnets and staging environments the gas price is routinely near the minimum.
4. The existing test `test_run_pre_validation_checks` uses `BlockInfo::default()` (which yields the minimum `NonzeroGasPrice`) and only passes because the test hardcodes `min_gas_price_percentage = 100`; changing it to 80 would silently pass the zero-price transaction. [4](#0-3) 

### Recommendation

Replace `to_integer()` (floor) with ceiling division so that a fractional threshold is always rounded up to at least 1 when the product is non-zero:

```rust
// Before (floor — collapses to 0 when product < 1):
let threshold = (gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0)
    .to_integer();

// After (ceiling — preserves the intent):
let threshold_ratio = gas_price_threshold_multiplier
    * previous_block_l2_gas_price.get().0;
let threshold = threshold_ratio.ceil().to_integer();
```

`Ratio::ceil()` from `num-rational` returns `⌈n/d⌉`, ensuring that any non-zero product yields a threshold of at least 1. This is consistent with how the codebase already handles similar conversions — for example `convert_l1_to_l2_gas_price_round_up` and `l1_gas_to_sierra_gas_amount_round_up` both explicitly use `.ceil()` to avoid under-counting: [5](#0-4) 

### Proof of Concept

```rust
use num_rational::Ratio;

fn main() {
    // Operator sets min_gas_price_percentage = 80 (documented example).
    // Previous block L2 gas price = 1 FRI/gas (bootstrap / minimum NonzeroGasPrice).
    let min_gas_price_percentage: u128 = 80;
    let previous_block_l2_gas_price: u128 = 1;

    let multiplier = Ratio::new(min_gas_price_percentage, 100_u128);
    let threshold = (multiplier * previous_block_l2_gas_price).to_integer();

    // threshold == 0  →  check `tx_price < 0` is always false for u128
    assert_eq!(threshold, 0);

    // A transaction with max_price_per_unit = 0 passes:
    let tx_l2_gas_price: u128 = 0;
    assert!(!(tx_l2_gas_price < threshold), "check bypassed — tx admitted");

    // With ceiling the threshold would be 1 and the tx would be rejected:
    let threshold_ceil = (multiplier * previous_block_l2_gas_price).ceil().to_integer();
    assert_eq!(threshold_ceil, 1);
    assert!(tx_l2_gas_price < threshold_ceil, "tx correctly rejected");
}
```

### Citations

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

**File:** crates/apollo_gateway_config/src/config.rs (L285-286)
```rust
    // Minimum gas price as percentage of threshold to accept transactions.
    pub min_gas_price_percentage: u8, // E.g., 80 to require 80% of threshold.
```

**File:** crates/apollo_gateway/src/stateful_transaction_validator_test.rs (L77-129)
```rust
// TODO(Arni): consider testing declare and deploy account.
#[rstest]
#[case::valid_tx(false, Ok(false))]
#[case::invalid_tx(
    true,
    Err(StarknetError {
        code: StarknetErrorCode::UnknownErrorCode(
            "StarknetErrorCode.GAS_PRICE_TOO_LOW".to_string(),
        ),
        message: "Transaction L2 gas price 0 is below the required threshold 1.".to_string(),
    })
)]
#[tokio::test]
async fn test_run_pre_validation_checks(
    #[case] zero_gas_fee: bool,
    #[case] expected_result: Result<bool, StarknetError>,
) {
    let account_nonce = nonce!(0);

    let mut mock_mempool_client = MockMempoolClient::new();
    mock_mempool_client.expect_account_tx_in_pool_or_recent_block().returning(|_| {
        // The mempool does not have any transactions from the sender.
        Ok(false)
    });
    mock_mempool_client.expect_validate_tx().returning(|_| Ok(()));
    let mempool_client = Arc::new(mock_mempool_client);

    let mut mock_gateway_fixed_block = MockGatewayFixedBlockStateReader::new();
    mock_gateway_fixed_block.expect_get_block_info().returning(|| Ok(BlockInfo::default()));

    let stateful_validator: StatefulTransactionValidator<TestStateReader, _> =
        StatefulTransactionValidator {
            config: StatefulTransactionValidatorConfig::default(),
            chain_info: ChainInfo::create_for_testing(),
            state_reader_and_contract_manager: None,
            gateway_fixed_block_state_reader: mock_gateway_fixed_block,
        };

    let resource_bounds = if zero_gas_fee {
        ValidResourceBounds::AllResources(AllResourceBounds {
            l2_gas: ResourceBounds { max_price_per_unit: 0_u128.into(), ..Default::default() },
            ..Default::default()
        })
    } else {
        ValidResourceBounds::create_for_testing()
    };
    let executable_tx: AccountTransaction = executable_invoke_tx(invoke_tx_args!(resource_bounds));

    let result = stateful_validator
        .run_pre_validation_checks(&executable_tx, account_nonce, mempool_client)
        .await;
    assert_eq!(result, expected_result);
}
```

**File:** crates/blockifier/src/blockifier_versioned_constants.rs (L369-387)
```rust
    /// Converts from L1 gas price to L2 gas price with **upward rounding**, based on the
    /// conversion of a Cairo step from Sierra gas to L1 gas.
    pub fn convert_l1_to_l2_gas_price_round_up(&self, l1_gas_price: GasPrice) -> GasPrice {
        (*(resource_cost_to_u128_ratio(self.sierra_gas_in_l1_gas_amount()) * l1_gas_price.0)
            .ceil()
            .numer())
        .into()
    }

    /// Converts L1 gas amount to Sierra (L2) gas amount with **upward rounding**.
    pub fn l1_gas_to_sierra_gas_amount_round_up(&self, l1_gas_amount: GasAmount) -> GasAmount {
        // The amount ratio is the inverse of the price ratio.
        (*(self.sierra_gas_in_l1_gas_amount().inv() * l1_gas_amount.0).ceil().numer()).into()
    }

    /// Converts Sierra (L2) gas amount to L1 gas amount with **upward rounding**.
    pub fn sierra_gas_to_l1_gas_amount_round_up(&self, l2_gas_amount: GasAmount) -> GasAmount {
        (*(self.sierra_gas_in_l1_gas_amount() * l2_gas_amount.0).ceil().numer()).into()
    }
```
