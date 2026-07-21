### Title
Gateway Stateful Validator Omits L1 Gas Price and L1 Data Gas Price Threshold Checks, Admitting Transactions That Will Fail Execution - (File: crates/apollo_gateway/src/stateful_transaction_validator.rs)

### Summary

The gateway's `validate_tx_l2_gas_price_within_threshold` function only validates the L2 gas price for `AllResources` transactions and performs no gas price validation at all for `L1Gas` transactions. Neither the stateless validator nor the mempool's `ValidationArgs` check L1 gas price or L1 data gas price against the current market price. This allows any unprivileged user to submit transactions with zero (or arbitrarily low) L1 gas price or L1 data gas price that pass all gateway and mempool admission checks, enter the mempool, and only fail during blockifier pre-validation — wasting sequencer resources and enabling mempool flooding.

### Finding Description

`StatefulTransactionValidator::validate_tx_l2_gas_price_within_threshold` at lines 358–390 of `crates/apollo_gateway/src/stateful_transaction_validator.rs` matches only on `ValidResourceBounds::AllResources` and, within that arm, reads only `l2_gas.max_price_per_unit`:

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
            // threshold check on l2_gas only
        }
        ValidResourceBounds::L1Gas(_) => {
            // No validation required for legacy transactions.
        }
    }
    Ok(())
}
``` [1](#0-0) 

`l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` are never compared against the current market price in either the stateless or stateful gateway path. The stateless validator's `validate_resource_bounds` also only checks `l2_gas.max_price_per_unit` against a static configured floor:

```rust
if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
    return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow { ... });
}
``` [2](#0-1) 

The mempool's `ValidationArgs` struct carries only `max_l2_gas_price`; L1 and L1-data gas prices are not forwarded to the mempool at all:

```rust
pub struct ValidationArgs {
    pub address: ContractAddress,
    pub account_nonce: Nonce,
    pub tx_hash: TransactionHash,
    pub tx_nonce: Nonce,
    pub tip: Tip,
    pub max_l2_gas_price: GasPrice,
}
``` [3](#0-2) 

The mempool's `validate_tx` therefore only checks nonce validity and fee escalation — not L1 gas price: [4](#0-3) 

The first place that actually enforces L1 gas price bounds is the blockifier's `check_fee_bounds` inside `perform_pre_validation_stage`, which runs only when the batcher attempts to execute the transaction:

```rust
if resource_bounds.max_price_per_unit < actual_gas_price.get() {
    insufficiencies_resource.push(ResourceBoundsError::MaxGasPriceTooLow { ... });
}
``` [5](#0-4) 

The gap between gateway admission and blockifier rejection is the exploitable window.

### Impact Explanation

This matches the **High** impact category: *"Mempool/gateway/RPC admission accepts invalid transactions or rejects valid transactions before sequencing."*

An unprivileged attacker can craft `AllResources` transactions with `l1_gas.max_price_per_unit = 0` and `l1_data_gas.max_price_per_unit = 0` while setting `l2_gas.max_price_per_unit` just above the configured static floor. Every such transaction passes the stateless validator (total `max_possible_fee > 0`, L2 price ≥ floor), passes the stateful validator (only L2 price is threshold-checked), passes mempool admission (only L2 price is in `ValidationArgs`), and occupies a mempool slot. When the batcher pulls the transaction and the blockifier runs `check_fee_bounds`, it immediately fails with `MaxGasPriceTooLow` for L1 gas. The transaction is never included in a block, but it consumed gateway CPU (including the blockifier `__validate__` entry-point run), mempool memory, and batcher execution budget before being discarded.

At scale this constitutes a low-cost denial-of-service: the attacker pays only the cost of submitting RPC calls; the sequencer pays the cost of stateful validation (including spawning a blocking task for blockifier validation) and batcher execution for each poisoned transaction.

### Likelihood Explanation

The attack requires no special privilege, no existing account balance, and no knowledge of internal state. Any user with RPC access can submit such transactions. The TODO comment in the source (`// TODO(Arni): Consider running this validation for all gas prices.`) confirms the gap is known but unmitigated. [6](#0-5) 

### Recommendation

Extend `validate_tx_l2_gas_price_within_threshold` (or rename it to `validate_tx_gas_prices_within_threshold`) to also compare `l1_gas.max_price_per_unit` and `l1_data_gas.max_price_per_unit` against the corresponding previous-block prices (fetched from `get_block_info()`) using the same percentage-threshold logic already applied to L2 gas. Add `max_l1_gas_price` and `max_l1_data_gas_price` to `ValidationArgs` so the mempool can enforce the same floor. The stateless validator should similarly extend its static-floor check to cover all three resource dimensions.

### Proof of Concept

1. Construct a V3 `InvokeTransaction` with `ValidResourceBounds::AllResources` where:
   - `l1_gas.max_price_per_unit = 0`
   - `l1_data_gas.max_price_per_unit = 0`
   - `l2_gas.max_price_per_unit = config.min_gas_price` (e.g., 1)
   - `l2_gas.max_amount = 1` (makes `max_possible_fee = 1 > 0`)
2. Submit via `starknet_addInvokeTransaction` RPC.
3. **Stateless validator** passes: `max_possible_fee = 1 ≠ 0`; `l2_gas.max_price_per_unit ≥ min_gas_price`. [7](#0-6) 
4. **Stateful validator** passes: `validate_tx_l2_gas_price_within_threshold` checks only `l2_gas.max_price_per_unit`, which meets the threshold. [8](#0-7) 
5. **Mempool** passes: `ValidationArgs` carries only `max_l2_gas_price`; nonce and fee-escalation checks pass for a fresh account. [9](#0-8) 
6. Transaction sits in the mempool. When the batcher calls `get_txs` and the blockifier runs `perform_pre_validation_stage` → `check_fee_bounds`, it finds `l1_gas.max_price_per_unit (0) < actual_l1_gas_price (> 0)` and raises `MaxGasPriceTooLow`. The transaction is discarded without being included in a block. [5](#0-4) 
7. Repeat at high frequency to exhaust mempool capacity and batcher execution budget.

### Citations

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

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L60-88)
```rust
        if !self.config.validate_resource_bounds {
            return Ok(());
        }

        let resource_bounds = *tx.resource_bounds();
        // The resource bounds should be positive even without the tip.
        if ValidResourceBounds::AllResources(resource_bounds).max_possible_fee(Tip::ZERO) == Fee(0)
        {
            return Err(StatelessTransactionValidatorError::ZeroResourceBounds { resource_bounds });
        }

        if resource_bounds.l2_gas.max_price_per_unit.0 < self.config.min_gas_price {
            return Err(StatelessTransactionValidatorError::MaxGasPriceTooLow {
                gas_price: resource_bounds.l2_gas.max_price_per_unit,
                min_gas_price: self.config.min_gas_price,
            });
        }

        // TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
        if let RpcTransaction::Declare(_) = tx {
        } else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
            return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
                gas_amount: resource_bounds.l2_gas.max_amount,
                max_gas_amount: self.config.max_l2_gas_amount,
            });
        }

        Ok(())
    }
```

**File:** crates/apollo_mempool_types/src/mempool_types.rs (L49-57)
```rust
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct ValidationArgs {
    pub address: ContractAddress,
    pub account_nonce: Nonce,
    pub tx_hash: TransactionHash,
    pub tx_nonce: Nonce,
    pub tip: Tip,
    pub max_l2_gas_price: GasPrice,
}
```

**File:** crates/apollo_mempool_types/src/mempool_types.rs (L59-69)
```rust
impl ValidationArgs {
    pub fn new(tx: &AccountTransaction, account_nonce: Nonce) -> Self {
        Self {
            address: tx.sender_address(),
            account_nonce,
            tx_hash: tx.tx_hash(),
            tx_nonce: tx.nonce(),
            tip: tx.tip(),
            max_l2_gas_price: tx.resource_bounds().get_l2_bounds().max_price_per_unit,
        }
    }
```

**File:** crates/apollo_mempool/src/mempool.rs (L402-408)
```rust
    pub fn validate_tx(&mut self, args: ValidationArgs) -> MempoolResult<()> {
        let tx_reference = (&args).into();
        self.validate_incoming_tx(tx_reference, args.account_nonce)?;
        self.validate_fee_escalation(tx_reference)?;

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
