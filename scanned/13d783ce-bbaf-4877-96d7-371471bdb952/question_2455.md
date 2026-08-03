# Q2455: schedule-cleanup mismatch via polkadotxcm execute on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::execute` on Collectives Polkadot runtime and control preimages, deposits, and dispatchable calls whose execution is later scheduled or referendum-driven so that `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}` makes open user submission paths disagree with later dispatch, deposit, or cleanup logic about what was authorized, breaking the invariant that scheduled or post-referendum consequences must stay bound to the exact authorized preimage and deposit state, and leading to critical - unauthorized privileged execution with direct user or treasury loss?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}`
- Entrypoint: `PolkadotXcm::execute`
- Attacker controls: preimages, deposits, and dispatchable calls whose execution is later scheduled or referendum-driven
- Exploit idea: makes open user submission paths disagree with later dispatch, deposit, or cleanup logic about what was authorized
- Invariant to test: scheduled or post-referendum consequences must stay bound to the exact authorized preimage and deposit state
- Expected Immunefi impact: Critical - unauthorized privileged execution with direct user or treasury loss
- Fast validation: xcm test if the path depends on aliased pluralities or remote execution
