# Q1792: allowance accounting in verifier::check_and_compute_new_allowance

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling repeated calls sized just under the remaining allowance, drive `runtime/runtime/src/verifier.rs::check_and_compute_new_allowance` to spend beyond the key allowance because the deduction is computed after the fact, breaking the invariant that allowance is decremented by the full cost before the call executes, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `runtime/runtime/src/verifier.rs` -> `check_and_compute_new_allowance`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: repeated calls sized just under the remaining allowance
- Exploit idea: spend beyond the key allowance because the deduction is computed after the fact
- Invariant to test: allowance is decremented by the full cost before the call executes
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a unit test next to the verifier tests and assert the exact `InvalidTxError` variant instead of acceptance
