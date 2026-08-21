# Q3222: deposit through restricted key in access_keys::action_delete_key

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling a `FunctionCall` action with a non-zero deposit under a restricted key, drive `runtime/runtime/src/access_keys.rs::action_delete_key` to attach value to a call that a function-call key must never be able to fund, breaking the invariant that function-call access keys can never move NEAR as a deposit, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `runtime/runtime/src/access_keys.rs` -> `action_delete_key`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: a `FunctionCall` action with a non-zero deposit under a restricted key
- Exploit idea: attach value to a call that a function-call key must never be able to fund
- Invariant to test: function-call access keys can never move NEAR as a deposit
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a unit test next to the verifier tests and assert the exact `InvalidTxError` variant instead of acceptance
