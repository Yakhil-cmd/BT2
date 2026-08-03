# Q2488: referendum replay via proxy proxy multisig as on Collectives Polkadot runtime

## Question
Can an unprivileged attacker enter through `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all` on Collectives Polkadot runtime and control preimages, deposits, and dispatchable calls whose execution is later scheduled or referendum-driven so that `impl_runtime_apis! / XCM payment and dry-run APIs` makes open user submission paths disagree with later dispatch, deposit, or cleanup logic about what was authorized, breaking the invariant that XCM-assisted execution must not strand or duplicate collective-related funds, and leading to high - severe scheduling or queue corruption with concrete protocol impact?

## Target
- File/function: `system-parachains/collectives/collectives-polkadot/src/lib.rs` :: `impl_runtime_apis! / XCM payment and dry-run APIs`
- Entrypoint: `Proxy::proxy` / `Multisig::as_multi` / `Utility::batch_all`
- Attacker controls: preimages, deposits, and dispatchable calls whose execution is later scheduled or referendum-driven
- Exploit idea: makes open user submission paths disagree with later dispatch, deposit, or cleanup logic about what was authorized
- Invariant to test: XCM-assisted execution must not strand or duplicate collective-related funds
- Expected Immunefi impact: High - severe scheduling or queue corruption with concrete protocol impact
- Fast validation: stateful fuzz test over batched proxy/XCM/preimage combinations
