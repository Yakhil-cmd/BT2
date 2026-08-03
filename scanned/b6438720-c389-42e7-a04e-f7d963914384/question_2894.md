# Q2894: identity-deposit drift via polkadotxcm execute send on People Kusama runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{execute, send}` on People Kusama runtime and control asset transfers, proxy calls, and XCM execution bundled around identity lifecycle operations so that `impl_runtime_apis! / XCM payment and dry-run APIs` creates a path where identity-related state changes and asset-moving calls disagree about the effective owner or beneficiary, breaking the invariant that signed users must never reach registrar or admin-like effects through batching, proxying, or XCM aliasing, and leading to critical - direct loss of funds through misrouted refund, slash, or asset movement?

## Target
- File/function: `system-parachains/people/people-kusama/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `PolkadotXcm::{execute, send}`
- Attacker controls: asset transfers, proxy calls, and XCM execution bundled around identity lifecycle operations
- Exploit idea: creates a path where identity-related state changes and asset-moving calls disagree about the effective owner or beneficiary
- Invariant to test: signed users must never reach registrar or admin-like effects through batching, proxying, or XCM aliasing
- Expected Immunefi impact: Critical - direct loss of funds through misrouted refund, slash, or asset movement
- Fast validation: runtime integration test around identity set, clear, sub-account, and refund sequencing
