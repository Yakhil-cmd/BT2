[1](#0-0) [2](#0-1)

### Citations

**File:** crates/sui-transaction-checks/src/lib.rs (L8-9)
```rust
#[sui_macros::with_checked_arithmetic]
mod checked {
```

**File:** crates/sui-transaction-checks/src/lib.rs (L412-419)
```rust
        let gas_status = if is_gasless {
            debug_assert_ne!(reference_gas_price, 0);
            let rgp = reference_gas_price.max(1);
            let compute_cap = protocol_config.gasless_max_computation_units() * rgp;
            SuiGasStatus::new(compute_cap, rgp, reference_gas_price, protocol_config)?
        } else {
            SuiGasStatus::new(gas_budget, gas_price, reference_gas_price, protocol_config)?
        };
```
