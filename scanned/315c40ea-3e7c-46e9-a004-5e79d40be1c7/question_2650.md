# Q2650: identity-deposit drift via polkadotxcm execute send on People Polkadot runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{execute, send}` on People Polkadot runtime and control asset transfers, proxy calls, and XCM execution bundled around identity lifecycle operations so that `construct_runtime! / RuntimeCall::{Identity, Assets, PolkadotXcm, Proxy, Utility}` makes proxy, multisig, or XCM execution observe a different account state than the identity logic uses for charges or refunds, breaking the invariant that identity slashing and treasury routing must not leak funds to attacker-chosen beneficiaries, and leading to critical - direct loss of funds through misrouted refund, slash, or asset movement?

## Target
- File/function: `system-parachains/people/people-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Identity, Assets, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `PolkadotXcm::{execute, send}`
- Attacker controls: asset transfers, proxy calls, and XCM execution bundled around identity lifecycle operations
- Exploit idea: makes proxy, multisig, or XCM execution observe a different account state than the identity logic uses for charges or refunds
- Invariant to test: identity slashing and treasury routing must not leak funds to attacker-chosen beneficiaries
- Expected Immunefi impact: Critical - direct loss of funds through misrouted refund, slash, or asset movement
- Fast validation: stateful fuzz test over identity fields, usernames, and accompanying asset transitions
