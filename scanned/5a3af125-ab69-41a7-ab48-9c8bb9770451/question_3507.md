# Q3507: method-name allowlist bypass in verifier::verify_function_call_permission

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling method name bytes including separators, empty names, and non-UTF8 sequences, drive `runtime/runtime/src/verifier.rs::verify_function_call_permission` to call a method outside the key's `method_names` allowlist, breaking the invariant that a function-call key can only invoke methods in its explicit allowlist, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `runtime/runtime/src/verifier.rs` -> `verify_function_call_permission`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: method name bytes including separators, empty names, and non-UTF8 sequences
- Exploit idea: call a method outside the key's `method_names` allowlist
- Invariant to test: a function-call key can only invoke methods in its explicit allowlist
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a unit test next to the verifier tests and assert the exact `InvalidTxError` variant instead of acceptance
