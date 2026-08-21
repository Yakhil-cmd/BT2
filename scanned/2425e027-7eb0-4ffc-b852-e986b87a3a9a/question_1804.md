# Q1804: function-call key receiver check in verifier::verify_function_call_permission

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling `receiver_id` casing, trailing bytes, and sub-account suffixes, drive `runtime/runtime/src/verifier.rs::verify_function_call_permission` to invoke a receiver the restricted key is not permitted to call, breaking the invariant that a function-call key can only target the exact `receiver_id` it was created with, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `runtime/runtime/src/verifier.rs` -> `verify_function_call_permission`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: `receiver_id` casing, trailing bytes, and sub-account suffixes
- Exploit idea: invoke a receiver the restricted key is not permitted to call
- Invariant to test: a function-call key can only target the exact `receiver_id` it was created with
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a unit test next to the verifier tests and assert the exact `InvalidTxError` variant instead of acceptance
