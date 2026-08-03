# Q2446: collective-origin widening via proxy proxy multisig as on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on Collectives Polkadot runtime and control XCM messages and beneficiaries that interact with the same balance or scheduling state so that `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}` induces a state where execution succeeds but deposit, refund, or scheduling state remains inconsistent, breaking the invariant that preimage and referendum-related deposits must be debited, refunded, and consumed exactly once, and leading to critical - unauthorized privileged execution with direct user or treasury loss?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: XCM messages and beneficiaries that interact with the same balance or scheduling state
- Exploit idea: induces a state where execution succeeds but deposit, refund, or scheduling state remains inconsistent
- Invariant to test: preimage and referendum-related deposits must be debited, refunded, and consumed exactly once
- Expected Immunefi impact: Critical - unauthorized privileged execution with direct user or treasury loss
- Fast validation: runtime integration test over preimage, submit, schedule, and cleanup ordering
