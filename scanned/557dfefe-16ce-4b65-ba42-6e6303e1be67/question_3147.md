# Q3147: CRC20 send_to_ibc burn backing under same-block reorder sender consistency

## Question
Can an unprivileged attacker enter through public send_to_ibc(string,uint) by controlling recipient, amount and caller token balance when two attacker-controlled transactions are valid separately but reordered in one block, then emit IBC send event not exactly matched by caller balance burn so that every bridge event equals the same caller balance and totalSupply burn fails and Cosmos address bytes, EVM addresses, tx signers, and event senders name the same principal, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: contracts/src/ModuleCRC20.sol::send_to_ibc
- Entrypoint: public send_to_ibc(string,uint)
- Attacker controls: recipient, amount and caller token balance; scenario focus: same-block reorder plus sender consistency.
- Exploit idea: emit IBC send event not exactly matched by caller balance burn while two attacker-controlled transactions are valid separately but reordered in one block.
- Invariant to test: every bridge event equals the same caller balance and totalSupply burn; also verify Cosmos address bytes, EVM addresses, tx signers, and event senders name the same principal.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: fuzz the controlled fields while asserting the invariant and rejecting any profitable state delta. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
