# Q2498: collective-origin widening via referenda signed submission and on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Referenda` signed submission and deposit path on Collectives Polkadot runtime and control batched combinations of proxy, preimage, referenda, and XCM execution so that `impl_runtime_apis! / XCM payment and dry-run APIs` makes open user submission paths disagree with later dispatch, deposit, or cleanup logic about what was authorized, breaking the invariant that signed users must not escalate into privileged collective execution through batching, proxying, or XCM aliasing, and leading to high - severe scheduling or queue corruption with concrete protocol impact?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Referenda` signed submission and deposit path
- Attacker controls: batched combinations of proxy, preimage, referenda, and XCM execution
- Exploit idea: makes open user submission paths disagree with later dispatch, deposit, or cleanup logic about what was authorized
- Invariant to test: signed users must not escalate into privileged collective execution through batching, proxying, or XCM aliasing
- Expected Immunefi impact: High - severe scheduling or queue corruption with concrete protocol impact
- Fast validation: xcm test if the path depends on aliased pluralities or remote execution
