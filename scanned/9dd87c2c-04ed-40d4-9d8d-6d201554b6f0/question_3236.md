# Q3236: CRC21 source send lock under failed tail call event binding

## Question
Can an unprivileged attacker enter through public send_to_ibc(string,uint,uint,bytes) by controlling recipient, amount, channel_id, extraData, isSource and allowance when a later bank, EVM, IBC, or callback step fails after earlier fund-sensitive work has run, then emit IBC send event for source token without exact module_address lock so that source sends lock exactly amount before native IBC transfer fails and recognized EVM logs are accepted only when backed by the contract state transition that emitted them, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: contracts/src/ModuleCRC21.sol::send_to_ibc
- Entrypoint: public send_to_ibc(string,uint,uint,bytes)
- Attacker controls: recipient, amount, channel_id, extraData, isSource and allowance; scenario focus: failed tail call plus event binding.
- Exploit idea: emit IBC send event for source token without exact module_address lock while a later bank, EVM, IBC, or callback step fails after earlier fund-sensitive work has run.
- Invariant to test: source sends lock exactly amount before native IBC transfer; also verify recognized EVM logs are accepted only when backed by the contract state transition that emitted them.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: build a local integration test with two accounts and compare state root plus balances before and after the attempted flow. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
