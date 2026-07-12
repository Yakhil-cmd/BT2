# Q2393: bank precompile readonly guard under nested execution backing conservation

## Question
Can an unprivileged attacker enter through STATICCALL or readonly EVM call to bank precompile by controlling method selector, calldata and readonly flag when a native action, precompile, or module EVM call triggers another hook, callback, or state transition, then mutate bank state through a supposedly readonly precompile call so that readonly calls cannot change bank balances or supply fails and escrowed, burned, minted, locked, and released amounts conserve value exactly, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/precompiles/bank.go::Run
- Entrypoint: STATICCALL or readonly EVM call to bank precompile
- Attacker controls: method selector, calldata and readonly flag; scenario focus: nested execution plus backing conservation.
- Exploit idea: mutate bank state through a supposedly readonly precompile call while a native action, precompile, or module EVM call triggers another hook, callback, or state transition.
- Invariant to test: readonly calls cannot change bank balances or supply; also verify escrowed, burned, minted, locked, and released amounts conserve value exactly.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: replay the same transaction sequence from exported genesis and assert deterministic balances and mappings. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
