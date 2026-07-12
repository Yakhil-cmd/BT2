# Q2965: ICA submitMsgs ownership under address alias channel provenance

## Question
Can an unprivileged attacker enter through EVM call to ICA precompile submitMsgs by controlling connectionID, packet data, timeout and EVM caller when EVM, bech32, module, zero, or precompile-range addresses are chosen to collide semantically, then submit interchain-account messages for an account not owned by the caller so that ICA owner is derived from contract.Caller for all value-moving sends fails and IBC channel, packet, and denom trace identity cannot be attacker-selected or replayed, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/precompiles/ica.go::Run submitMsgs
- Entrypoint: EVM call to ICA precompile submitMsgs
- Attacker controls: connectionID, packet data, timeout and EVM caller; scenario focus: address alias plus channel provenance.
- Exploit idea: submit interchain-account messages for an account not owned by the caller while EVM, bech32, module, zero, or precompile-range addresses are chosen to collide semantically.
- Invariant to test: ICA owner is derived from contract.Caller for all value-moving sends; also verify IBC channel, packet, and denom trace identity cannot be attacker-selected or replayed.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: write a focused unit test around the named function and assert pre/post bank, module, and contract balances. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
