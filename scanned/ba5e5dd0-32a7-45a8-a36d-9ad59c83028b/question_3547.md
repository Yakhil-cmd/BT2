# Q3547: CRC20 proxy send_to_ibc backing under same-block reorder sender consistency

## Question
Can an unprivileged attacker enter through public proxy send_to_ibc by controlling recipient, amount, channel_id, extraData, source flag and underlying CRC20 allowance when two attacker-controlled transactions are valid separately but reordered in one block, then emit an IBC event while underlying CRC20 moved or burned a different amount so that proxy event amount equals underlying CRC20 locked or burned amount fails and Cosmos address bytes, EVM addresses, tx signers, and event senders name the same principal, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: contracts/src/ModuleCRC20Proxy.sol::send_to_ibc
- Entrypoint: public proxy send_to_ibc
- Attacker controls: recipient, amount, channel_id, extraData, source flag and underlying CRC20 allowance; scenario focus: same-block reorder plus sender consistency.
- Exploit idea: emit an IBC event while underlying CRC20 moved or burned a different amount while two attacker-controlled transactions are valid separately but reordered in one block.
- Invariant to test: proxy event amount equals underlying CRC20 locked or burned amount; also verify Cosmos address bytes, EVM addresses, tx signers, and event senders name the same principal.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: fuzz the controlled fields while asserting the invariant and rejecting any profitable state delta. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
