# Q2425: preimage-deposit drift via referenda signed submission and on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Referenda` signed submission and deposit path on Collectives Polkadot runtime and control batched combinations of proxy, preimage, referenda, and XCM execution so that `impl_runtime_apis! / XCM payment and dry-run APIs` creates a path where a signed user indirectly reaches a more privileged origin or wider call surface than intended, breaking the invariant that preimage and referendum-related deposits must be debited, refunded, and consumed exactly once, and leading to critical - unauthorized privileged execution with direct user or treasury loss?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Referenda` signed submission and deposit path
- Attacker controls: batched combinations of proxy, preimage, referenda, and XCM execution
- Exploit idea: creates a path where a signed user indirectly reaches a more privileged origin or wider call surface than intended
- Invariant to test: preimage and referendum-related deposits must be debited, refunded, and consumed exactly once
- Expected Immunefi impact: Critical - unauthorized privileged execution with direct user or treasury loss
- Fast validation: stateful fuzz test over batched proxy/XCM/preimage combinations
