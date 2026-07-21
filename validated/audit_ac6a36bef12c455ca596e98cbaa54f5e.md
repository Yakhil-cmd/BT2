The bypass is real and fully confirmed by the production code. Here is the complete analysis:

---

### Title
Stateless Gateway Skips `max_l2_gas_amount` Check for Declare Transactions — (`crates/apollo_gateway/src/stateless_transaction_validator.rs`)

### Summary
`StatelessTransactionValidator::validate_resource_bounds` contains an explicit empty branch that causes the `max_l2_gas_amount` guard to be silently skipped for every `RpcTransaction::Declare`. An attacker can submit a `DeclareV3` transaction with `l2_gas.max_amount = GasAmount(u64::MAX)` and it will pass stateless gateway validation unconditionally, regardless of the configured `max_l2_gas_amount` limit.

### Finding Description

In `validate_resource_bounds`, after the `min_gas_price` check, the code reads:

```rust
// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.
if let RpcTransaction::Declare(_) = tx {
} else if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh { ... });
}
``` [1](#0-0) 

The `if let RpcTransaction::Declare(_) = tx {}` arm is an intentionally empty block. When the transaction is a Declare, the entire `else if` branch is unreachable. The `max_l2_gas_amount` bound — configured at `1,210,000,000` in production — is never evaluated for Declare transactions. [2](#0-1) 

The existing test `valid_l2_gas_amount_on_declare` explicitly asserts `Ok(())` for a Declare with `max_amount: GasAmount(200)` against a config with `max_l2_gas_amount: 100`, confirming this is the current behavior: [3](#0-2) 

Conversely, `test_invalid_max_l2_gas_amount` only parameterizes over `TransactionType::DeployAccount` and `TransactionType::Invoke` — Declare is explicitly excluded from the rejection test: [4](#0-3) 

### Impact Explanation

The `max_l2_gas_amount` gateway check exists to prevent transactions from claiming more L2 gas than the block can accommodate. For Invoke and DeployAccount, a transaction with `l2_gas.max_amount > max_l2_gas_amount` is rejected at the stateless gateway. For Declare, no such rejection occurs.

**Concrete corrupted admission value**: A `DeclareV3` with `l2_gas.max_amount = GasAmount(u64::MAX)` passes `StatelessTransactionValidator::validate` and is admitted to the mempool. The admission decision is wrong — the transaction exceeds the configured gateway policy limit but is accepted.

**Downstream execution impact is bounded**: The bouncer (`BouncerWeights`) tracks `sierra_gas` and `receipt_l2_gas` from actual execution results, not from declared `max_amount`: [5](#0-4) 

The post-execution fee check (`check_actual_cost_within_bounds`) compares actual gas used against `max_amount`. With `max_amount = u64::MAX`, this check trivially passes, meaning the transaction executes and the user pays actual gas costs. There is no block-capacity DoS and no economic harm to the sequencer from a single transaction.

**However**, the admission policy is concretely bypassed: the gateway accepts a Declare that it is configured to reject. Any downstream logic that relies on the invariant "admitted transactions have `l2_gas.max_amount ≤ max_l2_gas_amount`" (e.g., mempool capacity accounting, fee estimation upper bounds, future bouncer pre-checks) operates on a corrupted input.

### Likelihood Explanation

Trivially exploitable by any unprivileged user. No special state, account balance, or sequencer access is required. The attacker simply constructs a `DeclareV3` RPC transaction with `l2_gas.max_amount = GasAmount(u64::MAX)` and submits it to the public gateway endpoint. The bypass is unconditional — it applies to every Declare transaction regardless of any other field values.

### Recommendation

Remove the empty Declare exemption branch and apply the same `max_l2_gas_amount` guard uniformly:

```rust
if resource_bounds.l2_gas.max_amount.0 > self.config.max_l2_gas_amount {
    return Err(StatelessTransactionValidatorError::MaxGasAmountTooHigh {
        gas_amount: resource_bounds.l2_gas.max_amount,
        max_gas_amount: self.config.max_l2_gas_amount,
    });
}
```

The TODO comment `// TODO(Arni): Consider adding a validation for max_l2_gas_amount for declare.` should be resolved by applying the check. The test `valid_l2_gas_amount_on_declare` should be updated to assert an error, and `test_invalid_max_l2_gas_amount` should include `TransactionType::Declare` in its parameterization.

### Proof of Concept

The existing test `valid_l2_gas_amount_on_declare` already serves as a proof of concept. A minimal Rust unit test confirming the bypass:

```rust
let config = StatelessTransactionValidatorConfig {
    validate_resource_bounds: true,
    max_l2_gas_amount: 1_210_000_000, // production value
    min_gas_price: 1,
    ..Default::default()
};
let validator = StatelessTransactionValidator { config };

let tx = rpc_tx_for_testing(
    TransactionType::Declare,
    RpcTransactionArgs {
        resource_bounds: AllResourceBounds {
            l2_gas: ResourceBounds {
                max_amount: GasAmount(u64::MAX),
                max_price_per_unit: GasPrice(1),
            },
            ..Default::default()
        },
        ..Default::default()
    },
);

// Passes — max_l2_gas_amount check is skipped for Declare
assert_matches!(validator.validate(&tx), Ok(()));
``` [6](#0-5)

### Citations

**File:** crates/apollo_gateway/src/stateless_transaction_validator.rs (L56-88)
```rust
    fn validate_resource_bounds(
        &self,
        tx: &RpcTransaction,
    ) -> StatelessTransactionValidatorResult<()> {
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

**File:** crates/apollo_node/resources/config_schema.json (L3172-3176)
```json
  "gateway_config.static_config.stateless_tx_validator_config.max_l2_gas_amount": {
    "description": "Maximum allowed L2 gas amount for transactions.",
    "privacy": "Public",
    "value": 1210000000
  },
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L173-201)
```rust
#[rstest]
#[case::l2_gas_amount_out_of_limit(
    StatelessTransactionValidatorConfig {
        validate_resource_bounds: true,
        max_l2_gas_amount: 100,
        ..*DEFAULT_VALIDATOR_CONFIG_FOR_TESTING
    },
    RpcTransactionArgs {
        resource_bounds: AllResourceBounds {
            l2_gas: ResourceBounds {
                max_amount: GasAmount(200),
                ..NON_EMPTY_RESOURCE_BOUNDS
            },
            ..Default::default()
        },
        ..Default::default()
    }
)]
fn valid_l2_gas_amount_on_declare(
    #[case] config: StatelessTransactionValidatorConfig,
    #[case] rpc_tx_args: RpcTransactionArgs,
) {
    let tx_type = TransactionType::Declare;
    let tx_validator = StatelessTransactionValidator { config };

    let tx = rpc_tx_for_testing(tx_type, rpc_tx_args);

    assert_matches!(tx_validator.validate(&tx), Ok(()));
}
```

**File:** crates/apollo_gateway/src/stateless_transaction_validator_test.rs (L260-271)
```rust
fn test_invalid_max_l2_gas_amount(
    #[case] rpc_tx_args: RpcTransactionArgs,
    #[case] expected_error: StatelessTransactionValidatorError,
    #[values(TransactionType::DeployAccount, TransactionType::Invoke)] tx_type: TransactionType,
) {
    let tx_validator =
        StatelessTransactionValidator { config: DEFAULT_VALIDATOR_CONFIG.to_owned() };

    let tx = rpc_tx_for_testing(tx_type, rpc_tx_args);

    assert_eq!(tx_validator.validate(&tx).unwrap_err(), expected_error);
}
```

**File:** crates/blockifier/src/bouncer.rs (L155-168)
```rust
pub struct BouncerWeights {
    pub l1_gas: usize,
    pub message_segment_length: usize,
    pub n_events: usize,
    pub state_diff_size: usize,
    pub sierra_gas: GasAmount,
    pub n_txs: usize,
    pub proving_gas: GasAmount,
    /// Receipt-based L2 gas, including execution gas + state allocation costs + DA costs.
    /// Used to close blocks on the economic gas metric. Diverges from sierra_gas because
    /// it includes allocation_cost for new storage keys and other non-execution costs.
    // NOTE: Must stay in sync with orchestrator_versioned_constants' max_block_size.
    pub receipt_l2_gas: GasAmount,
}
```
