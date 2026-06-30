### Title
Broken or Paused External ETH Connector Contract Blocks All Token Operations Including Withdrawals - (File: `engine/src/contract_methods/connector.rs`)

### Summary
The Aurora Engine delegates every critical user-facing token operation to an external, configurable ETH connector contract via the `return_promise` helper. If that external contract fails for any reason (bug, storage exhaustion, or