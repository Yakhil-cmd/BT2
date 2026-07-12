# Q2101: bank precompile burn authority under amount boundary atomicity

## Question
Can an unprivileged attacker enter through EVM call to bank precompile burn by controlling address argument, amount and caller contract when the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid, then burn another account balance and alter redeemability or accounting so that burn destroys only balances controlled by the EVM caller or intended token path fails and no partial native, EVM, IBC, or token state can commit on an error path, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/precompiles/bank.go::Run burn
- Entrypoint: EVM call to bank precompile burn
- Attacker controls: address argument, amount and caller contract; scenario focus: amount boundary plus atomicity.
- Exploit idea: burn another account balance and alter redeemability or accounting while the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid.
- Invariant to test: burn destroys only balances controlled by the EVM caller or intended token path; also verify no partial native, EVM, IBC, or token state can commit on an error path.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: build a local integration test with two accounts and compare state root plus balances before and after the attempted flow. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
