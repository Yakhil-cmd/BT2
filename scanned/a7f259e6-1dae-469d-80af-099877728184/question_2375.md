# Q2375: bank precompile readonly guard under ABI/protobuf edge channel provenance

## Question
Can an unprivileged attacker enter through STATICCALL or readonly EVM call to bank precompile by controlling method selector, calldata and readonly flag when calldata, log data, topics, or protobuf bytes decode successfully but contain edge-case field encodings, then mutate bank state through a supposedly readonly precompile call so that readonly calls cannot change bank balances or supply fails and IBC channel, packet, and denom trace identity cannot be attacker-selected or replayed, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/precompiles/bank.go::Run
- Entrypoint: STATICCALL or readonly EVM call to bank precompile
- Attacker controls: method selector, calldata and readonly flag; scenario focus: ABI/protobuf edge plus channel provenance.
- Exploit idea: mutate bank state through a supposedly readonly precompile call while calldata, log data, topics, or protobuf bytes decode successfully but contain edge-case field encodings.
- Invariant to test: readonly calls cannot change bank balances or supply; also verify IBC channel, packet, and denom trace identity cannot be attacker-selected or replayed.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: write a focused unit test around the named function and assert pre/post bank, module, and contract balances. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
