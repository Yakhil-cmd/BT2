# Q3456: precompile set construction and pausing promise side-effect order near hardfork-specific address maps in `new_prague` and earlier constructors

## Question
Can an attacker make hardfork-specific address maps in `new_prague` and earlier constructors emit logs, promise requests, or other side effects before the final error condition is known, leaving an exploitable mismatch that causes Theft of gas?

## Target
- File/function: `engine-precompiles/src/lib.rs + engine/src/pausables.rs + engine/src/engine.rs::create_precompiles` -> `hardfork-specific address maps in `new_prague` and earlier constructors`
- Entrypoint: any public EVM execution path that constructs Aurora’s precompile set and then calls a precompile address
- Attacker controls: public EVM calldata, chosen precompile address, gas limit, and ordering around pause-flag changes already configured on-chain
- Exploit idea: seek a side effect that escapes before the targeted precompile’s final validity check.
- Invariant to test: paused precompiles must stay unreachable and every reachable precompile must charge cost and emit logs consistently for the selected hardfork
- Expected Immunefi impact: Theft of gas
- Fast validation: Force the last failing condition after any intermediate side effect and assert nothing externally visible survives. write EVM tests that target multiple precompile addresses under paused and unpaused configurations, then assert address resolution, cost accounting, and reachability match expectations
