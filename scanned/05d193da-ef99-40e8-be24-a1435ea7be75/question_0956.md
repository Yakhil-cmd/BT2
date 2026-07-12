# Q0956: token mapping permission under replay attempt event binding

## Question
Can an unprivileged attacker enter through MsgUpdateTokenMapping by controlling sender field, signer, denom, contract, symbol and decimals when the attacker repeats a previously successful or failed packet, tx, event, or callback, then register a malicious contract for a valuable denom without CanChangeTokenMapping so that only authorized signers can create, replace or delete token mappings fails and recognized EVM logs are accepted only when backed by the contract state transition that emitted them, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/msg_server.go::UpdateTokenMapping
- Entrypoint: MsgUpdateTokenMapping
- Attacker controls: sender field, signer, denom, contract, symbol and decimals; scenario focus: replay attempt plus event binding.
- Exploit idea: register a malicious contract for a valuable denom without CanChangeTokenMapping while the attacker repeats a previously successful or failed packet, tx, event, or callback.
- Invariant to test: only authorized signers can create, replace or delete token mappings; also verify recognized EVM logs are accepted only when backed by the contract state transition that emitted them.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: build a local integration test with two accounts and compare state root plus balances before and after the attempted flow. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
