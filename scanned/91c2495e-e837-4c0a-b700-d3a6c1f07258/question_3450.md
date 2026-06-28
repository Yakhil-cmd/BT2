# Q3450: precompile set construction and pausing resource amplification through hardfork-specific address maps in `new_prague` and earlier constructors

## Question
Can an attacker batch or repeat calls to hardfork-specific address maps in `new_prague` and earlier constructors through any public EVM execution path that constructs Aurora’s precompile set and then calls a precompile address so a small paid input expands into disproportionate CPU, memory, or promise work and causes Temporary freezing of funds?

## Target
- File/function: `engine-precompiles/src/lib.rs + engine/src/pausables.rs + engine/src/engine.rs::create_precompiles` -> `hardfork-specific address maps in `new_prague` and earlier constructors`
- Entrypoint: any public EVM execution path that constructs Aurora’s precompile set and then calls a precompile address
- Attacker controls: public EVM calldata, chosen precompile address, gas limit, and ordering around pause-flag changes already configured on-chain
- Exploit idea: amplify a per-call underpricing or allocation bug at the named precompile.
- Invariant to test: paused precompiles must stay unreachable and every reachable precompile must charge cost and emit logs consistently for the selected hardfork
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Run a high-count local sequence and compare cumulative paid gas with measured work and any resulting balance drain. write EVM tests that target multiple precompile addresses under paused and unpaused configurations, then assert address resolution, cost accounting, and reachability match expectations
