# Q1664: action attachment overflow in ext::append_action_deterministic_state_init

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling attached gas and deposits summing near the integer bound, drive `runtime/runtime/src/ext.rs::append_action_deterministic_state_init` to overflow the prepaid gas or deposit accounting, breaking the invariant that attached gas and deposits are summed with checked arithmetic, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `runtime/runtime/src/ext.rs` -> `append_action_deterministic_state_init`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: attached gas and deposits summing near the integer bound
- Exploit idea: overflow the prepaid gas or deposit accounting
- Invariant to test: attached gas and deposits are summed with checked arithmetic
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a proptest/invariant test that randomises the inputs and asserts the accounting identity holds for every generated case
