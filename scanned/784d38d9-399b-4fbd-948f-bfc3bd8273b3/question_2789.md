# Q2789: gas attachment underflow in dependencies::append_action_deploy_contract

## Question
Can an unprivileged attacker who runs an attacker contract that emits receipts via `promise_batch_action_*` host calls, controlling attached gas equal to zero, the maximum, or the remaining budget, drive `runtime/near-vm-runner/src/logic/dependencies.rs::append_action_deploy_contract` to attach more gas than the call actually holds, breaking the invariant that attached gas never exceeds the caller's remaining unburnt gas, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `runtime/near-vm-runner/src/logic/dependencies.rs` -> `append_action_deploy_contract`
- Entrypoint: unprivileged attacker runs an attacker contract that emits receipts via `promise_batch_action_*` host calls
- Attacker controls: attached gas equal to zero, the maximum, or the remaining budget
- Exploit idea: attach more gas than the call actually holds
- Invariant to test: attached gas never exceeds the caller's remaining unburnt gas
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
