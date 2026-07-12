# Q2950: ICA submitMsgs ownership under same-block reorder supply integrity

## Question
Can an unprivileged attacker enter through EVM call to ICA precompile submitMsgs by controlling connectionID, packet data, timeout and EVM caller when two attacker-controlled transactions are valid separately but reordered in one block, then submit interchain-account messages for an account not owned by the caller so that ICA owner is derived from contract.Caller for all value-moving sends fails and bank supply, module escrow, contract balances, and ERC totalSupply cannot diverge profitably, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/precompiles/ica.go::Run submitMsgs
- Entrypoint: EVM call to ICA precompile submitMsgs
- Attacker controls: connectionID, packet data, timeout and EVM caller; scenario focus: same-block reorder plus supply integrity.
- Exploit idea: submit interchain-account messages for an account not owned by the caller while two attacker-controlled transactions are valid separately but reordered in one block.
- Invariant to test: ICA owner is derived from contract.Caller for all value-moving sends; also verify bank supply, module escrow, contract balances, and ERC totalSupply cannot diverge profitably.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: write a focused unit test around the named function and assert pre/post bank, module, and contract balances. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
