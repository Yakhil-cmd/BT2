After thorough analysis of the codebase, I have identified a valid analog vulnerability.

---

### Title
Gateway Admits Unsigned Invoke Transactions via `skip_stateful_validations` Bypass — (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

### Summary

The `skip_stateful_validations` function in the gateway's stateful transaction validator unconditionally bypasses the `__validate__` entry point (account signature verification) for any Invoke transaction with `n