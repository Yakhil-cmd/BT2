# Q0606: EVM-denom IBC withdrawal rounding under amount boundary event binding

## Question
Can an unprivileged attacker enter through MsgTransferTokens with EVM denom by controlling from, destination, amount near 10^10, and account balance when the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid, then turn decimal remainder handling into an over-release of IBC CRO so that burned EVM denom divided by 10^10 equals IBC CRO sent and remainder stays local fails and recognized EVM logs are accepted only when backed by the contract state transition that emitted them, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/ibc.go::IbcTransferCoins
- Entrypoint: MsgTransferTokens with EVM denom
- Attacker controls: from, destination, amount near 10^10, and account balance; scenario focus: amount boundary plus event binding.
- Exploit idea: turn decimal remainder handling into an over-release of IBC CRO while the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid.
- Invariant to test: burned EVM denom divided by 10^10 equals IBC CRO sent and remainder stays local; also verify recognized EVM logs are accepted only when backed by the contract state transition that emitted them.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: build a local integration test with two accounts and compare state root plus balances before and after the attempted flow. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
