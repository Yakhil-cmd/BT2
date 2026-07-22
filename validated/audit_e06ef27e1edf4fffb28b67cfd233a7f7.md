### Title
Gateway Admits Invoke Transactions with Unverified Signatures via `skip_stateful_validations` Bypass - (File: `crates/apollo_gateway/src/stateful_transaction_validator.rs`)

---

### Summary

The `skip_stateful_validations` function in the gateway's stateful transaction validator unconditionally skips the `__validate__` entry point (the