# Q3606: cross-ceremony state bleed via polkadotxcm execute send on Encointer runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{execute, send}` on Encointer runtime and control community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts so that `impl_runtime_apis! / XCM payment and dry-run APIs` replays or reorders a valid community artifact so two modules consume it as fresh state, breaking the invariant that batched or proxied execution must not let a user bypass ceremony or community isolation rules, and leading to critical - unbacked or duplicated community balances?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `PolkadotXcm::{execute, send}`
- Attacker controls: community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts
- Exploit idea: replays or reorders a valid community artifact so two modules consume it as fresh state
- Invariant to test: batched or proxied execution must not let a user bypass ceremony or community isolation rules
- Expected Immunefi impact: Critical - unbacked or duplicated community balances
- Fast validation: stateful fuzz test that reorders offline-payment, reputation, and treasury actions across boundaries
