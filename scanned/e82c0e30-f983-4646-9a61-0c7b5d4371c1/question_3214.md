# Q3214: CRC21 source send lock under duplicate ordering mapping uniqueness

## Question
Can an unprivileged attacker enter through public send_to_ibc(string,uint,uint,bytes) by controlling recipient, amount, channel_id, extraData, isSource and allowance when the attacker repeats or reorders value-bearing items inside one transaction or receipt, then emit IBC send event for source token without exact module_address lock so that source sends lock exactly amount before native IBC transfer fails and one denom maps to one contract and one contract maps to one redeemable denom, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: contracts/src/ModuleCRC21.sol::send_to_ibc
- Entrypoint: public send_to_ibc(string,uint,uint,bytes)
- Attacker controls: recipient, amount, channel_id, extraData, isSource and allowance; scenario focus: duplicate ordering plus mapping uniqueness.
- Exploit idea: emit IBC send event for source token without exact module_address lock while the attacker repeats or reorders value-bearing items inside one transaction or receipt.
- Invariant to test: source sends lock exactly amount before native IBC transfer; also verify one denom maps to one contract and one contract maps to one redeemable denom.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: use a malicious minimal EVM contract or marshaled protobuf payload to exercise the entrypoint and inspect all state diffs. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
