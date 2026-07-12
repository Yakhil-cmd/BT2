# Q0999: token mapping permission under nested execution cross-phase equality

## Question
Can an unprivileged attacker enter through MsgUpdateTokenMapping by controlling sender field, signer, denom, contract, symbol and decimals when a native action, precompile, or module EVM call triggers another hook, callback, or state transition, then register a malicious contract for a valuable denom without CanChangeTokenMapping so that only authorized signers can create, replace or delete token mappings fails and CheckTx, proposal verification, execution, export/import, and replay see the same message and state, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/msg_server.go::UpdateTokenMapping
- Entrypoint: MsgUpdateTokenMapping
- Attacker controls: sender field, signer, denom, contract, symbol and decimals; scenario focus: nested execution plus cross-phase equality.
- Exploit idea: register a malicious contract for a valuable denom without CanChangeTokenMapping while a native action, precompile, or module EVM call triggers another hook, callback, or state transition.
- Invariant to test: only authorized signers can create, replace or delete token mappings; also verify CheckTx, proposal verification, execution, export/import, and replay see the same message and state.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: use a malicious minimal EVM contract or marshaled protobuf payload to exercise the entrypoint and inspect all state diffs. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
