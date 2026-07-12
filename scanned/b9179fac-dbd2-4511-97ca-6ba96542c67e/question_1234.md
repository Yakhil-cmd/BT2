# Q1234: source-denom contract validation under failed tail call mapping uniqueness

## Question
Can an unprivileged attacker enter through MsgUpdateTokenMapping or auto mapping by controlling cronos0x denom casing, contract hex form and source flag when a later bank, EVM, IBC, or callback step fails after earlier fund-sensitive work has run, then normalize a source denom into a non-derived contract mapping so that source denom address exactly matches the contract encoded in the denom fails and one denom maps to one contract and one contract maps to one redeemable denom, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/keeper.go::validateContractAddressForSourceDenom
- Entrypoint: MsgUpdateTokenMapping or auto mapping
- Attacker controls: cronos0x denom casing, contract hex form and source flag; scenario focus: failed tail call plus mapping uniqueness.
- Exploit idea: normalize a source denom into a non-derived contract mapping while a later bank, EVM, IBC, or callback step fails after earlier fund-sensitive work has run.
- Invariant to test: source denom address exactly matches the contract encoded in the denom; also verify one denom maps to one contract and one contract maps to one redeemable denom.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: use a malicious minimal EVM contract or marshaled protobuf payload to exercise the entrypoint and inspect all state diffs. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
