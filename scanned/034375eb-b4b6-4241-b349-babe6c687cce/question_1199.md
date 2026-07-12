# Q1199: external mapping deletion fallback under nested execution cross-phase equality

## Question
Can an unprivileged attacker enter through MsgUpdateTokenMapping deleting a mapping by controlling denom with external and auto mappings plus reverse key when a native action, precompile, or module EVM call triggers another hook, callback, or state transition, then delete an external mapping so fallback auto mapping redirects valuable withdrawals so that mapping deletion cannot rebind a denom to attacker-controlled code fails and CheckTx, proposal verification, execution, export/import, and replay see the same message and state, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/keeper.go::DeleteExternalContractForDenom
- Entrypoint: MsgUpdateTokenMapping deleting a mapping
- Attacker controls: denom with external and auto mappings plus reverse key; scenario focus: nested execution plus cross-phase equality.
- Exploit idea: delete an external mapping so fallback auto mapping redirects valuable withdrawals while a native action, precompile, or module EVM call triggers another hook, callback, or state transition.
- Invariant to test: mapping deletion cannot rebind a denom to attacker-controlled code; also verify CheckTx, proposal verification, execution, export/import, and replay see the same message and state.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: use a malicious minimal EVM contract or marshaled protobuf payload to exercise the entrypoint and inspect all state diffs. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
