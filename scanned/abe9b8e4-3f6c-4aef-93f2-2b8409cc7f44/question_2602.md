# Q2602: proxy-assisted identity escape via polkadotxcm execute send on People Polkadot runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{execute, send}` on People Polkadot runtime and control asset transfers, proxy calls, and XCM execution bundled around identity lifecycle operations so that `impl_runtime_apis! / XCM payment and dry-run APIs` creates a path where identity-related state changes and asset-moving calls disagree about the effective owner or beneficiary, breaking the invariant that identity deposits and refunds must always reconcile with the final asset balances, and leading to critical - direct loss of funds through misrouted refund, slash, or asset movement?

## Target
- File/function: `system-parachains/people/people-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `PolkadotXcm::{execute, send}`
- Attacker controls: asset transfers, proxy calls, and XCM execution bundled around identity lifecycle operations
- Exploit idea: creates a path where identity-related state changes and asset-moving calls disagree about the effective owner or beneficiary
- Invariant to test: identity deposits and refunds must always reconcile with the final asset balances
- Expected Immunefi impact: Critical - direct loss of funds through misrouted refund, slash, or asset movement
- Fast validation: stateful fuzz test over identity fields, usernames, and accompanying asset transitions
