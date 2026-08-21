# Q2074: burnt vs used divergence in gas::saturating_div

## Question
Can an unprivileged attacker who calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments, controlling a call that fails after prepaying for promises, drive `core/primitives-core/src/gas.rs::saturating_div` to make burnt gas and used gas disagree in the attacker's favour, breaking the invariant that used gas always equals burnt gas plus outstanding prepaid gas, and leading to direct loss of funds / unauthorized token minting?

## Target
- File/function: `core/primitives-core/src/gas.rs` -> `saturating_div`
- Entrypoint: unprivileged attacker calls a deployed contract with a `FunctionCall` action carrying attacker-chosen arguments
- Attacker controls: a call that fails after prepaying for promises
- Exploit idea: make burnt gas and used gas disagree in the attacker's favour
- Invariant to test: used gas always equals burnt gas plus outstanding prepaid gas
- Expected Immunefi impact: Critical - direct loss of funds / unauthorized token minting
- Fast validation: add a case to `runtime/runtime/src/tests/apply.rs` and assert the balance checker and gas totals with `cargo test -p node-runtime --features test_features`
