# Q3593: community-treasury drift via polkadotxcm execute send on Encointer runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{execute, send}` on Encointer runtime and control community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts so that `impl_runtime_apis! / XCM payment and dry-run APIs` replays or reorders a valid community artifact so two modules consume it as fresh state, breaking the invariant that each reputation, meetup result, offline payment, or treasury claim must be consumable exactly once and only in its own context, and leading to critical - direct loss of funds or community treasury drain?

## Target
- File/function: `system-parachains/encointer/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `PolkadotXcm::{execute, send}`
- Attacker controls: community ids, ceremony indices, meetup references, and participant-controlled reputation artifacts
- Exploit idea: replays or reorders a valid community artifact so two modules consume it as fresh state
- Invariant to test: each reputation, meetup result, offline payment, or treasury claim must be consumable exactly once and only in its own context
- Expected Immunefi impact: Critical - direct loss of funds or community treasury drain
- Fast validation: stateful fuzz test that reorders offline-payment, reputation, and treasury actions across boundaries
