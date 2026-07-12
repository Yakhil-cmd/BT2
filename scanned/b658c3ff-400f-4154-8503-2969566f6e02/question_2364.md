# Q2364: bank precompile readonly guard under address alias mapping uniqueness

## Question
Can an unprivileged attacker enter through STATICCALL or readonly EVM call to bank precompile by controlling method selector, calldata and readonly flag when EVM, bech32, module, zero, or precompile-range addresses are chosen to collide semantically, then mutate bank state through a supposedly readonly precompile call so that readonly calls cannot change bank balances or supply fails and one denom maps to one contract and one contract maps to one redeemable denom, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/precompiles/bank.go::Run
- Entrypoint: STATICCALL or readonly EVM call to bank precompile
- Attacker controls: method selector, calldata and readonly flag; scenario focus: address alias plus mapping uniqueness.
- Exploit idea: mutate bank state through a supposedly readonly precompile call while EVM, bech32, module, zero, or precompile-range addresses are chosen to collide semantically.
- Invariant to test: readonly calls cannot change bank balances or supply; also verify one denom maps to one contract and one contract maps to one redeemable denom.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: use a malicious minimal EVM contract or marshaled protobuf payload to exercise the entrypoint and inspect all state diffs. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
