# Q3460: precompile set construction and pausing recoverability gap after hardfork-specific address maps in `new_prague` and earlier constructors

## Question
Can an attacker make hardfork-specific address maps in `new_prague` and earlier constructors enter a failed state that neither cleanly reverts nor enables a safe refund or retry path, stranding funds or system capacity and causing Theft of gas?

## Target
- File/function: `engine-precompiles/src/lib.rs + engine/src/pausables.rs + engine/src/engine.rs::create_precompiles` -> `hardfork-specific address maps in `new_prague` and earlier constructors`
- Entrypoint: any public EVM execution path that constructs Aurora’s precompile set and then calls a precompile address
- Attacker controls: public EVM calldata, chosen precompile address, gas limit, and ordering around pause-flag changes already configured on-chain
- Exploit idea: target failure states around the precompile that are neither final success nor clean revert.
- Invariant to test: paused precompiles must stay unreachable and every reachable precompile must charge cost and emit logs consistently for the selected hardfork
- Expected Immunefi impact: Theft of gas
- Fast validation: Enumerate recoverability after each distinct failure mode and assert there is always one safe compensation path. write EVM tests that target multiple precompile addresses under paused and unpaused configurations, then assert address resolution, cost accounting, and reachability match expectations
