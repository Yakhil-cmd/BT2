# Q217: permission serialization in account::full_access

## Question
Can an unprivileged attacker who submits `Stake` / `DeleteAccount` / `AddKey` action sequences from its own account, controlling access key permission payloads at their encoding limits, drive `core/primitives-core/src/account.rs::full_access` to widen a key's stored permission through encoding, breaking the invariant that stored permissions decode exactly as they were authorised, and leading to unauthorized state modification of an account the attacker does not control?

## Target
- File/function: `core/primitives-core/src/account.rs` -> `full_access`
- Entrypoint: unprivileged attacker submits `Stake` / `DeleteAccount` / `AddKey` action sequences from its own account
- Attacker controls: access key permission payloads at their encoding limits
- Exploit idea: widen a key's stored permission through encoding
- Invariant to test: stored permissions decode exactly as they were authorised
- Expected Immunefi impact: Critical - unauthorized state modification of an account the attacker does not control
- Fast validation: add a proptest/invariant test that randomises the inputs and asserts the accounting identity holds for every generated case
