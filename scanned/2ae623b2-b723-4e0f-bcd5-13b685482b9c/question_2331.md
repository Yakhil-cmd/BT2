# Q2331: bank precompile readonly guard under failed tail call atomicity

## Question
Can an unprivileged attacker enter through STATICCALL or readonly EVM call to bank precompile by controlling method selector, calldata and readonly flag when a later bank, EVM, IBC, or callback step fails after earlier fund-sensitive work has run, then mutate bank state through a supposedly readonly precompile call so that readonly calls cannot change bank balances or supply fails and no partial native, EVM, IBC, or token state can commit on an error path, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/precompiles/bank.go::Run
- Entrypoint: STATICCALL or readonly EVM call to bank precompile
- Attacker controls: method selector, calldata and readonly flag; scenario focus: failed tail call plus atomicity.
- Exploit idea: mutate bank state through a supposedly readonly precompile call while a later bank, EVM, IBC, or callback step fails after earlier fund-sensitive work has run.
- Invariant to test: readonly calls cannot change bank balances or supply; also verify no partial native, EVM, IBC, or token state can commit on an error path.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: build a local integration test with two accounts and compare state root plus balances before and after the attempted flow. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
