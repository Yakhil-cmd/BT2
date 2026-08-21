# Q2004: limit config bypass in parameter_table::from_str

## Question
Can an unprivileged attacker who submits a single transaction carrying a large attacker-chosen batch of actions, controlling inputs exactly at each configured limit, drive `core/parameters/src/parameter_table.rs::from_str` to exceed a configured limit through an off-by-one in its check, breaking the invariant that every configured limit is enforced inclusively and consistently, and leading to greatly increasing the computational cost of the network (free or underpriced execution)?

## Target
- File/function: `core/parameters/src/parameter_table.rs` -> `from_str`
- Entrypoint: unprivileged attacker submits a single transaction carrying a large attacker-chosen batch of actions
- Attacker controls: inputs exactly at each configured limit
- Exploit idea: exceed a configured limit through an off-by-one in its check
- Invariant to test: every configured limit is enforced inclusively and consistently
- Expected Immunefi impact: High - greatly increasing the computational cost of the network (free or underpriced execution)
- Fast validation: add a case under `runtime/near-vm-runner/src/tests/` and diff burnt gas / outcome against the expected costs
