# Q0990: token mapping permission under remap window supply integrity

## Question
Can an unprivileged attacker enter through MsgUpdateTokenMapping by controlling sender field, signer, denom, contract, symbol and decimals when token mappings, params, permissions, or packet state change between check, execution, callback, or acknowledgement, then register a malicious contract for a valuable denom without CanChangeTokenMapping so that only authorized signers can create, replace or delete token mappings fails and bank supply, module escrow, contract balances, and ERC totalSupply cannot diverge profitably, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/msg_server.go::UpdateTokenMapping
- Entrypoint: MsgUpdateTokenMapping
- Attacker controls: sender field, signer, denom, contract, symbol and decimals; scenario focus: remap window plus supply integrity.
- Exploit idea: register a malicious contract for a valuable denom without CanChangeTokenMapping while token mappings, params, permissions, or packet state change between check, execution, callback, or acknowledgement.
- Invariant to test: only authorized signers can create, replace or delete token mappings; also verify bank supply, module escrow, contract balances, and ERC totalSupply cannot diverge profitably.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: write a focused unit test around the named function and assert pre/post bank, module, and contract balances. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
