# Q2647: proxy-assisted identity escape via polkadotxcm execute send on People Polkadot runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{execute, send}` on People Polkadot runtime and control XCM beneficiaries, aliasable locations, and identity-related slashing or refund conditions so that `impl_runtime_apis! / XCM payment and dry-run APIs` makes proxy, multisig, or XCM execution observe a different account state than the identity logic uses for charges or refunds, breaking the invariant that identity slashing and treasury routing must not leak funds to attacker-chosen beneficiaries, and leading to critical - direct loss of funds through misrouted refund, slash, or asset movement?

## Target
- File/function: `system-parachains/people/people-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `PolkadotXcm::{execute, send}`
- Attacker controls: XCM beneficiaries, aliasable locations, and identity-related slashing or refund conditions
- Exploit idea: makes proxy, multisig, or XCM execution observe a different account state than the identity logic uses for charges or refunds
- Invariant to test: identity slashing and treasury routing must not leak funds to attacker-chosen beneficiaries
- Expected Immunefi impact: Critical - direct loss of funds through misrouted refund, slash, or asset movement
- Fast validation: stateful fuzz test over identity fields, usernames, and accompanying asset transitions
