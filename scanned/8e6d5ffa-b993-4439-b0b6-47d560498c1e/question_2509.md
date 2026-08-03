# Q2509: collective-origin widening via proxy proxy multisig as on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on Collectives Polkadot runtime and control user-controlled inputs that feed plurality-like execution or post-deposit cleanup logic so that `impl_runtime_apis! / XCM payment and dry-run APIs` creates a path where a signed user indirectly reaches a more privileged origin or wider call surface than intended, breaking the invariant that signed users must not escalate into privileged collective execution through batching, proxying, or XCM aliasing, and leading to critical - permanent freeze or misrouting of deposits tied to collective flows?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: user-controlled inputs that feed plurality-like execution or post-deposit cleanup logic
- Exploit idea: creates a path where a signed user indirectly reaches a more privileged origin or wider call surface than intended
- Invariant to test: signed users must not escalate into privileged collective execution through batching, proxying, or XCM aliasing
- Expected Immunefi impact: Critical - permanent freeze or misrouting of deposits tied to collective flows
- Fast validation: runtime integration test over preimage, submit, schedule, and cleanup ordering
