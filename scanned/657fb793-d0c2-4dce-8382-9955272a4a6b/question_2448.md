# Q2448: referendum replay via referenda signed submission and on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Referenda` signed submission and deposit path on Collectives Polkadot runtime and control preimages, deposits, and dispatchable calls whose execution is later scheduled or referendum-driven so that `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}` creates a path where a signed user indirectly reaches a more privileged origin or wider call surface than intended, breaking the invariant that XCM-assisted execution must not strand or duplicate collective-related funds, and leading to critical - permanent freeze or misrouting of deposits tied to collective flows?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}`
- Entrypoint: `Referenda` signed submission and deposit path
- Attacker controls: preimages, deposits, and dispatchable calls whose execution is later scheduled or referendum-driven
- Exploit idea: creates a path where a signed user indirectly reaches a more privileged origin or wider call surface than intended
- Invariant to test: XCM-assisted execution must not strand or duplicate collective-related funds
- Expected Immunefi impact: Critical - permanent freeze or misrouting of deposits tied to collective flows
- Fast validation: xcm test if the path depends on aliased pluralities or remote execution
