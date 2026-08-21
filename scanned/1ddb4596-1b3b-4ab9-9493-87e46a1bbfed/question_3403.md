# Q3403: touched-node undercount in function_call::execute_function_call

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling access patterns that revisit nodes across a single receipt, drive `runtime/runtime/src/function_call.rs::execute_function_call` to avoid paying for trie nodes the execution actually touched, breaking the invariant that every touched trie node is charged exactly once per receipt, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `runtime/runtime/src/function_call.rs` -> `execute_function_call`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: access patterns that revisit nodes across a single receipt
- Exploit idea: avoid paying for trie nodes the execution actually touched
- Invariant to test: every touched trie node is charged exactly once per receipt
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
