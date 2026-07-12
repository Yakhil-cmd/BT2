# Q1106: external mapping deletion fallback under amount boundary event binding

## Question
Can an unprivileged attacker enter through MsgUpdateTokenMapping deleting a mapping by controlling denom with external and auto mappings plus reverse key when the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid, then delete an external mapping so fallback auto mapping redirects valuable withdrawals so that mapping deletion cannot rebind a denom to attacker-controlled code fails and recognized EVM logs are accepted only when backed by the contract state transition that emitted them, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/keeper.go::DeleteExternalContractForDenom
- Entrypoint: MsgUpdateTokenMapping deleting a mapping
- Attacker controls: denom with external and auto mappings plus reverse key; scenario focus: amount boundary plus event binding.
- Exploit idea: delete an external mapping so fallback auto mapping redirects valuable withdrawals while the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid.
- Invariant to test: mapping deletion cannot rebind a denom to attacker-controlled code; also verify recognized EVM logs are accepted only when backed by the contract state transition that emitted them.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: build a local integration test with two accounts and compare state root plus balances before and after the attempted flow. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
