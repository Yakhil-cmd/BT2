# Q3499: precompile set construction and pausing supply coupling bug at current-account and random-seed injection into constructor context

## Question
Can an attacker invoke current-account and random-seed injection into constructor context so that token supply, bridge supply, or escrow supply coupled to the precompile drifts from the actual burned or minted amount, causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine-precompiles/src/lib.rs + engine/src/pausables.rs + engine/src/engine.rs::create_precompiles` -> `current-account and random-seed injection into constructor context`
- Entrypoint: any public EVM execution path that constructs Aurora’s precompile set and then calls a precompile address
- Attacker controls: public EVM calldata, chosen precompile address, gas limit, and ordering around pause-flag changes already configured on-chain
- Exploit idea: check how the targeted precompile’s output is coupled to supply-moving code.
- Invariant to test: paused precompiles must stay unreachable and every reachable precompile must charge cost and emit logs consistently for the selected hardfork
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Track total supply, escrowed balances, and recipient balances before and after the crafted call sequence. write EVM tests that target multiple precompile addresses under paused and unpaused configurations, then assert address resolution, cost accounting, and reachability match expectations
