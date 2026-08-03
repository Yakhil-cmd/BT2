# Q2474: collective-origin widening via proxy proxy multisig as on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on Collectives Polkadot runtime and control batched combinations of proxy, preimage, referenda, and XCM execution so that `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}` lets a preimage, deposit, or scheduled effect be consumed more than once or cleaned up too early, breaking the invariant that scheduled or post-referendum consequences must stay bound to the exact authorized preimage and deposit state, and leading to critical - permanent freeze or misrouting of deposits tied to collective flows?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Alliance, FellowshipReferenda, AmbassadorReferenda, Preimage, Scheduler, Proxy, Utility, PolkadotXcm}`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: batched combinations of proxy, preimage, referenda, and XCM execution
- Exploit idea: lets a preimage, deposit, or scheduled effect be consumed more than once or cleaned up too early
- Invariant to test: scheduled or post-referendum consequences must stay bound to the exact authorized preimage and deposit state
- Expected Immunefi impact: Critical - permanent freeze or misrouting of deposits tied to collective flows
- Fast validation: xcm test if the path depends on aliased pluralities or remote execution
