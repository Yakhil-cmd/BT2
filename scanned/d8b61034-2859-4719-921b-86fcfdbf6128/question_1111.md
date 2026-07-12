# Q1111: external mapping deletion fallback under duplicate ordering atomicity

## Question
Can an unprivileged attacker enter through MsgUpdateTokenMapping deleting a mapping by controlling denom with external and auto mappings plus reverse key when the attacker repeats or reorders value-bearing items inside one transaction or receipt, then delete an external mapping so fallback auto mapping redirects valuable withdrawals so that mapping deletion cannot rebind a denom to attacker-controlled code fails and no partial native, EVM, IBC, or token state can commit on an error path, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/keeper.go::DeleteExternalContractForDenom
- Entrypoint: MsgUpdateTokenMapping deleting a mapping
- Attacker controls: denom with external and auto mappings plus reverse key; scenario focus: duplicate ordering plus atomicity.
- Exploit idea: delete an external mapping so fallback auto mapping redirects valuable withdrawals while the attacker repeats or reorders value-bearing items inside one transaction or receipt.
- Invariant to test: mapping deletion cannot rebind a denom to attacker-controlled code; also verify no partial native, EVM, IBC, or token state can commit on an error path.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: build a local integration test with two accounts and compare state root plus balances before and after the attempted flow. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
