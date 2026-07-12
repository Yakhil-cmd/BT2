# Q1004: stale reverse mapping under amount boundary mapping uniqueness

## Question
Can an unprivileged attacker enter through token mapping update reached by transaction flow by controlling denom, contract address and existing ContractToDenomKey when the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid, then turn stale reverse state into dual ownership of one backing contract so that one contract cannot redeem or mint value for two denoms fails and one denom maps to one contract and one contract maps to one redeemable denom, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/keeper.go::ensureContractNotMapped
- Entrypoint: token mapping update reached by transaction flow
- Attacker controls: denom, contract address and existing ContractToDenomKey; scenario focus: amount boundary plus mapping uniqueness.
- Exploit idea: turn stale reverse state into dual ownership of one backing contract while the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid.
- Invariant to test: one contract cannot redeem or mint value for two denoms; also verify one denom maps to one contract and one contract maps to one redeemable denom.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: use a malicious minimal EVM contract or marshaled protobuf payload to exercise the entrypoint and inspect all state diffs. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
