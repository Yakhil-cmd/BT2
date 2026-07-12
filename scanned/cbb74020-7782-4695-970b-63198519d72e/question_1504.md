# Q1504: send-to-IBC v1 sender binding under amount boundary mapping uniqueness

## Question
Can an unprivileged attacker enter through EVM tx emitting __CronosSendToIbc v1 by controlling sender in log data, recipient string, amount and mapped contract when the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid, then make the hook transfer or refund for a sender that did not burn or lock tokens so that log sender is authenticated to the economic token owner fails and one denom maps to one contract and one contract maps to one redeemable denom, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/evmhandlers/send_to_ibc.go::Handle
- Entrypoint: EVM tx emitting __CronosSendToIbc v1
- Attacker controls: sender in log data, recipient string, amount and mapped contract; scenario focus: amount boundary plus mapping uniqueness.
- Exploit idea: make the hook transfer or refund for a sender that did not burn or lock tokens while the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid.
- Invariant to test: log sender is authenticated to the economic token owner; also verify one denom maps to one contract and one contract maps to one redeemable denom.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: use a malicious minimal EVM contract or marshaled protobuf payload to exercise the entrypoint and inspect all state diffs. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
