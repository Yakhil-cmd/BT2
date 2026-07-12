# Q1614: send-to-IBC v2 topics under duplicate ordering mapping uniqueness

## Question
Can an unprivileged attacker enter through EVM tx emitting __CronosSendToIbc v2 by controlling indexed sender topic, channel_id topic, recipient, amount and extraData when the attacker repeats or reorders value-bearing items inside one transaction or receipt, then misdecode indexed topics into another sender or channel so that topic-derived sender and channel match the Solidity state transition fails and one denom maps to one contract and one contract maps to one redeemable denom, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/evmhandlers/send_to_ibc_v2.go::Handle
- Entrypoint: EVM tx emitting __CronosSendToIbc v2
- Attacker controls: indexed sender topic, channel_id topic, recipient, amount and extraData; scenario focus: duplicate ordering plus mapping uniqueness.
- Exploit idea: misdecode indexed topics into another sender or channel while the attacker repeats or reorders value-bearing items inside one transaction or receipt.
- Invariant to test: topic-derived sender and channel match the Solidity state transition; also verify one denom maps to one contract and one contract maps to one redeemable denom.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: use a malicious minimal EVM contract or marshaled protobuf payload to exercise the entrypoint and inspect all state diffs. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
