# Q0964: token mapping permission under address alias mapping uniqueness

## Question
Can an unprivileged attacker enter through MsgUpdateTokenMapping by controlling sender field, signer, denom, contract, symbol and decimals when EVM, bech32, module, zero, or precompile-range addresses are chosen to collide semantically, then register a malicious contract for a valuable denom without CanChangeTokenMapping so that only authorized signers can create, replace or delete token mappings fails and one denom maps to one contract and one contract maps to one redeemable denom, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/msg_server.go::UpdateTokenMapping
- Entrypoint: MsgUpdateTokenMapping
- Attacker controls: sender field, signer, denom, contract, symbol and decimals; scenario focus: address alias plus mapping uniqueness.
- Exploit idea: register a malicious contract for a valuable denom without CanChangeTokenMapping while EVM, bech32, module, zero, or precompile-range addresses are chosen to collide semantically.
- Invariant to test: only authorized signers can create, replace or delete token mappings; also verify one denom maps to one contract and one contract maps to one redeemable denom.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: use a malicious minimal EVM contract or marshaled protobuf payload to exercise the entrypoint and inspect all state diffs. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
