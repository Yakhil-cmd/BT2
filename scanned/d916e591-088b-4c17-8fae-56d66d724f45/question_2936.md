# Q2936: slash-routing confusion via polkadotxcm execute send on People Kusama runtime

## Question
Can an unprivileged attacker enter through `PolkadotXcm::{execute, send}` on People Kusama runtime and control asset transfers, proxy calls, and XCM execution bundled around identity lifecycle operations so that `impl_runtime_apis! / XCM payment and dry-run APIs` makes proxy, multisig, or XCM execution observe a different account state than the identity logic uses for charges or refunds, breaking the invariant that identity deposits and refunds must always reconcile with the final asset balances, and leading to critical - permanent freeze of identity or asset balances?

## Target
- File/function: `system-parachains/people/people-kusama/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `PolkadotXcm::{execute, send}`
- Attacker controls: asset transfers, proxy calls, and XCM execution bundled around identity lifecycle operations
- Exploit idea: makes proxy, multisig, or XCM execution observe a different account state than the identity logic uses for charges or refunds
- Invariant to test: identity deposits and refunds must always reconcile with the final asset balances
- Expected Immunefi impact: Critical - permanent freeze of identity or asset balances
- Fast validation: stateful fuzz test over identity fields, usernames, and accompanying asset transitions
