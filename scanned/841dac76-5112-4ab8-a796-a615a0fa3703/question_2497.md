# Q2497: preimage-deposit drift via proxy proxy multisig as on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on Collectives Polkadot runtime and control preimages, deposits, and dispatchable calls whose execution is later scheduled or referendum-driven so that `impl_runtime_apis! / XCM payment and dry-run APIs` creates a path where a signed user indirectly reaches a more privileged origin or wider call surface than intended, breaking the invariant that scheduled or post-referendum consequences must stay bound to the exact authorized preimage and deposit state, and leading to critical - unauthorized privileged execution with direct user or treasury loss?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: preimages, deposits, and dispatchable calls whose execution is later scheduled or referendum-driven
- Exploit idea: creates a path where a signed user indirectly reaches a more privileged origin or wider call surface than intended
- Invariant to test: scheduled or post-referendum consequences must stay bound to the exact authorized preimage and deposit state
- Expected Immunefi impact: Critical - unauthorized privileged execution with direct user or treasury loss
- Fast validation: stateful fuzz test over batched proxy/XCM/preimage combinations
