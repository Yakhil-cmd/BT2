# Q2623: sub-account lock reuse via assets transfer transfer approved on People Polkadot runtime

## Question
Can an unprivileged attacker enter through `Assets::{transfer, transfer_approved}` on People Polkadot runtime and control XCM beneficiaries, aliasable locations, and identity-related slashing or refund conditions so that `construct_runtime! / RuntimeCall::{Identity, Assets, PolkadotXcm, Proxy, Utility}` makes proxy, multisig, or XCM execution observe a different account state than the identity logic uses for charges or refunds, breaking the invariant that identity slashing and treasury routing must not leak funds to attacker-chosen beneficiaries, and leading to high - unauthorized execution against another account or beneficiary?

## Target
- File/function: `system-parachains/people/people-polkadot/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Identity, Assets, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `Assets::{transfer, transfer_approved}`
- Attacker controls: XCM beneficiaries, aliasable locations, and identity-related slashing or refund conditions
- Exploit idea: makes proxy, multisig, or XCM execution observe a different account state than the identity logic uses for charges or refunds
- Invariant to test: identity slashing and treasury routing must not leak funds to attacker-chosen beneficiaries
- Expected Immunefi impact: High - unauthorized execution against another account or beneficiary
- Fast validation: runtime integration test around identity set, clear, sub-account, and refund sequencing
