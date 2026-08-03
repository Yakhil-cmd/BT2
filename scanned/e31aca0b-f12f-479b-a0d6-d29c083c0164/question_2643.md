# Q2643: sub-account lock reuse via assets transfer transfer approved on People Polkadot runtime

## Question
Can an unprivileged attacker enter through `Assets::{transfer, transfer_approved}` on People Polkadot runtime and control asset transfers, proxy calls, and XCM execution bundled around identity lifecycle operations so that `impl_runtime_apis! / XCM payment and dry-run APIs` reuses or reorders user-controlled identity state so a deposit, refund, or lock is consumed twice or never released, breaking the invariant that a username, sub-account deposit, or identity lock must not be consumed twice or stranded forever, and leading to high - unauthorized execution against another account or beneficiary?

## Target
- File/function: `system-parachains/people/people-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Assets::{transfer, transfer_approved}`
- Attacker controls: asset transfers, proxy calls, and XCM execution bundled around identity lifecycle operations
- Exploit idea: reuses or reorders user-controlled identity state so a deposit, refund, or lock is consumed twice or never released
- Invariant to test: a username, sub-account deposit, or identity lock must not be consumed twice or stranded forever
- Expected Immunefi impact: High - unauthorized execution against another account or beneficiary
- Fast validation: xcm-emulator or proxy test if the path depends on aliased locations or nested execution
