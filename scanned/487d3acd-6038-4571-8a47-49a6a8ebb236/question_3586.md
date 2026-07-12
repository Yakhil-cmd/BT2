# Q3586: CRC20 proxy send_to_ibc backing under remap window event binding

## Question
Can an unprivileged attacker enter through public proxy send_to_ibc by controlling recipient, amount, channel_id, extraData, source flag and underlying CRC20 allowance when token mappings, params, permissions, or packet state change between check, execution, callback, or acknowledgement, then emit an IBC event while underlying CRC20 moved or burned a different amount so that proxy event amount equals underlying CRC20 locked or burned amount fails and recognized EVM logs are accepted only when backed by the contract state transition that emitted them, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: contracts/src/ModuleCRC20Proxy.sol::send_to_ibc
- Entrypoint: public proxy send_to_ibc
- Attacker controls: recipient, amount, channel_id, extraData, source flag and underlying CRC20 allowance; scenario focus: remap window plus event binding.
- Exploit idea: emit an IBC event while underlying CRC20 moved or burned a different amount while token mappings, params, permissions, or packet state change between check, execution, callback, or acknowledgement.
- Invariant to test: proxy event amount equals underlying CRC20 locked or burned amount; also verify recognized EVM logs are accepted only when backed by the contract state transition that emitted them.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: build a local integration test with two accounts and compare state root plus balances before and after the attempted flow. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
