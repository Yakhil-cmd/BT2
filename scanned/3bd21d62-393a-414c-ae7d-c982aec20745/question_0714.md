# Q0714: source channel routing under duplicate ordering mapping uniqueness

## Question
Can an unprivileged attacker enter through MsgTransferTokens or send_to_ibc for source coins by controlling channelId, source denom, destination and mapped contract when the attacker repeats or reorders value-bearing items inside one transaction or receipt, then route source-denom value through an unintended valid channel so that source coins leave only through the intended authenticated channel fails and one denom maps to one contract and one contract maps to one redeemable denom, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/ibc.go::ibcSendTransfer
- Entrypoint: MsgTransferTokens or send_to_ibc for source coins
- Attacker controls: channelId, source denom, destination and mapped contract; scenario focus: duplicate ordering plus mapping uniqueness.
- Exploit idea: route source-denom value through an unintended valid channel while the attacker repeats or reorders value-bearing items inside one transaction or receipt.
- Invariant to test: source coins leave only through the intended authenticated channel; also verify one denom maps to one contract and one contract maps to one redeemable denom.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: use a malicious minimal EVM contract or marshaled protobuf payload to exercise the entrypoint and inspect all state diffs. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
