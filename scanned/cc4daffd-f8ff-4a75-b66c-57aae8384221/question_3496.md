# Q3496: storage-stake enforcement in verifier::check_storage_stake

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling state growth that leaves the account below its storage staking requirement, drive `runtime/runtime/src/verifier.rs::check_storage_stake` to leave an account holding more state than its balance stakes for, breaking the invariant that every account always stakes enough balance for the state it holds, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/runtime/src/verifier.rs` -> `check_storage_stake`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: state growth that leaves the account below its storage staking requirement
- Exploit idea: leave an account holding more state than its balance stakes for
- Invariant to test: every account always stakes enough balance for the state it holds
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a unit test next to the verifier tests and assert the exact `InvalidTxError` variant instead of acceptance
