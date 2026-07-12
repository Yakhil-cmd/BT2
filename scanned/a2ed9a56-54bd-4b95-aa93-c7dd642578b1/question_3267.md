# Q3267: CRC21 source send lock under address alias sender consistency

## Question
Can an unprivileged attacker enter through public send_to_ibc(string,uint,uint,bytes) by controlling recipient, amount, channel_id, extraData, isSource and allowance when EVM, bech32, module, zero, or precompile-range addresses are chosen to collide semantically, then emit IBC send event for source token without exact module_address lock so that source sends lock exactly amount before native IBC transfer fails and Cosmos address bytes, EVM addresses, tx signers, and event senders name the same principal, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: contracts/src/ModuleCRC21.sol::send_to_ibc
- Entrypoint: public send_to_ibc(string,uint,uint,bytes)
- Attacker controls: recipient, amount, channel_id, extraData, isSource and allowance; scenario focus: address alias plus sender consistency.
- Exploit idea: emit IBC send event for source token without exact module_address lock while EVM, bech32, module, zero, or precompile-range addresses are chosen to collide semantically.
- Invariant to test: source sends lock exactly amount before native IBC transfer; also verify Cosmos address bytes, EVM addresses, tx signers, and event senders name the same principal.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: fuzz the controlled fields while asserting the invariant and rejecting any profitable state delta. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
