# Q2906: ICA submitMsgs ownership under amount boundary event binding

## Question
Can an unprivileged attacker enter through EVM call to ICA precompile submitMsgs by controlling connectionID, packet data, timeout and EVM caller when the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid, then submit interchain-account messages for an account not owned by the caller so that ICA owner is derived from contract.Caller for all value-moving sends fails and recognized EVM logs are accepted only when backed by the contract state transition that emitted them, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/precompiles/ica.go::Run submitMsgs
- Entrypoint: EVM call to ICA precompile submitMsgs
- Attacker controls: connectionID, packet data, timeout and EVM caller; scenario focus: amount boundary plus event binding.
- Exploit idea: submit interchain-account messages for an account not owned by the caller while the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid.
- Invariant to test: ICA owner is derived from contract.Caller for all value-moving sends; also verify recognized EVM logs are accepted only when backed by the contract state transition that emitted them.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: build a local integration test with two accounts and compare state root plus balances before and after the attempted flow. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
