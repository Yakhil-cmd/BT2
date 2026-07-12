# Q3594: CRC20 proxy send_to_ibc backing under nested execution mapping uniqueness

## Question
Can an unprivileged attacker enter through public proxy send_to_ibc by controlling recipient, amount, channel_id, extraData, source flag and underlying CRC20 allowance when a native action, precompile, or module EVM call triggers another hook, callback, or state transition, then emit an IBC event while underlying CRC20 moved or burned a different amount so that proxy event amount equals underlying CRC20 locked or burned amount fails and one denom maps to one contract and one contract maps to one redeemable denom, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: contracts/src/ModuleCRC20Proxy.sol::send_to_ibc
- Entrypoint: public proxy send_to_ibc
- Attacker controls: recipient, amount, channel_id, extraData, source flag and underlying CRC20 allowance; scenario focus: nested execution plus mapping uniqueness.
- Exploit idea: emit an IBC event while underlying CRC20 moved or burned a different amount while a native action, precompile, or module EVM call triggers another hook, callback, or state transition.
- Invariant to test: proxy event amount equals underlying CRC20 locked or burned amount; also verify one denom maps to one contract and one contract maps to one redeemable denom.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: use a malicious minimal EVM contract or marshaled protobuf payload to exercise the entrypoint and inspect all state diffs. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
