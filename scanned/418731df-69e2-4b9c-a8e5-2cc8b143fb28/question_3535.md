# Q3535: CRC20 proxy send_to_ibc backing under failed tail call channel provenance

## Question
Can an unprivileged attacker enter through public proxy send_to_ibc by controlling recipient, amount, channel_id, extraData, source flag and underlying CRC20 allowance when a later bank, EVM, IBC, or callback step fails after earlier fund-sensitive work has run, then emit an IBC event while underlying CRC20 moved or burned a different amount so that proxy event amount equals underlying CRC20 locked or burned amount fails and IBC channel, packet, and denom trace identity cannot be attacker-selected or replayed, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: contracts/src/ModuleCRC20Proxy.sol::send_to_ibc
- Entrypoint: public proxy send_to_ibc
- Attacker controls: recipient, amount, channel_id, extraData, source flag and underlying CRC20 allowance; scenario focus: failed tail call plus channel provenance.
- Exploit idea: emit an IBC event while underlying CRC20 moved or burned a different amount while a later bank, EVM, IBC, or callback step fails after earlier fund-sensitive work has run.
- Invariant to test: proxy event amount equals underlying CRC20 locked or burned amount; also verify IBC channel, packet, and denom trace identity cannot be attacker-selected or replayed.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: write a focused unit test around the named function and assert pre/post bank, module, and contract balances. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
