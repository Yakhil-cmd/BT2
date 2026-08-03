# Q2641: slash-routing confusion via identity set identity clear on People Polkadot runtime

## Question
Can an unprivileged attacker enter through `Identity::{set_identity, clear_identity, set_subs, request_judgement}` on People Polkadot runtime and control identity fields, username state, sub-account lists, and deposits packed into one signed flow so that `construct_runtime! / RuntimeCall::{Identity, Assets, PolkadotXcm, Proxy, Utility}` makes proxy, multisig, or XCM execution observe a different account state than the identity logic uses for charges or refunds, breaking the invariant that identity slashing and treasury routing must not leak funds to attacker-chosen beneficiaries, and leading to critical - direct loss of funds through misrouted refund, slash, or asset movement?

## Target
- File/function: `system-parachains/people/people-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Identity, Assets, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `Identity::{set_identity, clear_identity, set_subs, request_judgement}`
- Attacker controls: identity fields, username state, sub-account lists, and deposits packed into one signed flow
- Exploit idea: makes proxy, multisig, or XCM execution observe a different account state than the identity logic uses for charges or refunds
- Invariant to test: identity slashing and treasury routing must not leak funds to attacker-chosen beneficiaries
- Expected Immunefi impact: Critical - direct loss of funds through misrouted refund, slash, or asset movement
- Fast validation: xcm-emulator or proxy test if the path depends on aliased locations or nested execution
