# Q2887: refund-beneficiary mismatch via polkadotxcm execute send on People Kusama runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{execute, send}` on People Kusama runtime and control asset transfers, proxy calls, and XCM execution bundled around identity lifecycle operations so that `construct_runtime! / RuntimeCall::{Identity, PolkadotXcm, Proxy, Utility}` creates a path where identity-related state changes and asset-moving calls disagree about the effective owner or beneficiary, breaking the invariant that signed users must never reach registrar or admin-like effects through batching, proxying, or XCM aliasing, and leading to high - unauthorized execution against another account or beneficiary?

## Target
- File/function: `system-parachains/people/people-kusama/src/lib.rs` :: `construct_runtime! / RuntimeCall::{Identity, PolkadotXcm, Proxy, Utility}`
- Entrypoint: `PolkadotXcm::{execute, send}`
- Attacker controls: asset transfers, proxy calls, and XCM execution bundled around identity lifecycle operations
- Exploit idea: creates a path where identity-related state changes and asset-moving calls disagree about the effective owner or beneficiary
- Invariant to test: signed users must never reach registrar or admin-like effects through batching, proxying, or XCM aliasing
- Expected Immunefi impact: High - unauthorized execution against another account or beneficiary
- Fast validation: xcm-emulator or proxy test if the path depends on aliased locations or nested execution
