# Q3455: precompile set construction and pausing padding or canonicalization gap in hardfork-specific address maps in `new_prague` and earlier constructors

## Question
Can an attacker craft non-canonical but accepted input to hardfork-specific address maps in `new_prague` and earlier constructors through any public EVM execution path that constructs Aurora’s precompile set and then calls a precompile address, producing a useful output under one canonicalization but a different gas or validity path under another, and thus Permanent freezing of funds?

## Target
- File/function: `engine-precompiles/src/lib.rs + engine/src/pausables.rs + engine/src/engine.rs::create_precompiles` -> `hardfork-specific address maps in `new_prague` and earlier constructors`
- Entrypoint: any public EVM execution path that constructs Aurora’s precompile set and then calls a precompile address
- Attacker controls: public EVM calldata, chosen precompile address, gas limit, and ordering around pause-flag changes already configured on-chain
- Exploit idea: abuse non-canonical encodings at the targeted precompile.
- Invariant to test: paused precompiles must stay unreachable and every reachable precompile must charge cost and emit logs consistently for the selected hardfork
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Generate canonical and non-canonical representations of the same mathematical input and compare success, output, and charged gas. write EVM tests that target multiple precompile addresses under paused and unpaused configurations, then assert address resolution, cost accounting, and reachability match expectations
