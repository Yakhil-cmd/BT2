# Q1200: external mapping deletion fallback under nested execution supply integrity

## Question
Can an unprivileged attacker enter through MsgUpdateTokenMapping deleting a mapping by controlling denom with external and auto mappings plus reverse key when a native action, precompile, or module EVM call triggers another hook, callback, or state transition, then delete an external mapping so fallback auto mapping redirects valuable withdrawals so that mapping deletion cannot rebind a denom to attacker-controlled code fails and bank supply, module escrow, contract balances, and ERC totalSupply cannot diverge profitably, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/keeper.go::DeleteExternalContractForDenom
- Entrypoint: MsgUpdateTokenMapping deleting a mapping
- Attacker controls: denom with external and auto mappings plus reverse key; scenario focus: nested execution plus supply integrity.
- Exploit idea: delete an external mapping so fallback auto mapping redirects valuable withdrawals while a native action, precompile, or module EVM call triggers another hook, callback, or state transition.
- Invariant to test: mapping deletion cannot rebind a denom to attacker-controlled code; also verify bank supply, module escrow, contract balances, and ERC totalSupply cannot diverge profitably.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: write a focused unit test around the named function and assert pre/post bank, module, and contract balances. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
