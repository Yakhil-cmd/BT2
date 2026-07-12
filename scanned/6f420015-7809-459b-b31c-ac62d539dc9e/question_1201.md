# Q1201: source-denom contract validation under amount boundary atomicity

## Question
Can an unprivileged attacker enter through MsgUpdateTokenMapping or auto mapping by controlling cronos0x denom casing, contract hex form and source flag when the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid, then normalize a source denom into a non-derived contract mapping so that source denom address exactly matches the contract encoded in the denom fails and no partial native, EVM, IBC, or token state can commit on an error path, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/keeper.go::validateContractAddressForSourceDenom
- Entrypoint: MsgUpdateTokenMapping or auto mapping
- Attacker controls: cronos0x denom casing, contract hex form and source flag; scenario focus: amount boundary plus atomicity.
- Exploit idea: normalize a source denom into a non-derived contract mapping while the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid.
- Invariant to test: source denom address exactly matches the contract encoded in the denom; also verify no partial native, EVM, IBC, or token state can commit on an error path.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: build a local integration test with two accounts and compare state root plus balances before and after the attempted flow. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
