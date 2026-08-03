# Q2444: referendum replay via preimage note preimage unnote on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Preimage::{note_preimage, unnote_preimage}` on Collectives Polkadot runtime and control user-controlled inputs that feed plurality-like execution or post-deposit cleanup logic so that `impl_runtime_apis! / XCM payment and dry-run APIs` induces a state where execution succeeds but deposit, refund, or scheduling state remains inconsistent, breaking the invariant that preimage and referendum-related deposits must be debited, refunded, and consumed exactly once, and leading to critical - permanent freeze or misrouting of deposits tied to collective flows?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Preimage::{note_preimage, unnote_preimage}`
- Attacker controls: user-controlled inputs that feed plurality-like execution or post-deposit cleanup logic
- Exploit idea: induces a state where execution succeeds but deposit, refund, or scheduling state remains inconsistent
- Invariant to test: preimage and referendum-related deposits must be debited, refunded, and consumed exactly once
- Expected Immunefi impact: Critical - permanent freeze or misrouting of deposits tied to collective flows
- Fast validation: runtime integration test over preimage, submit, schedule, and cleanup ordering
