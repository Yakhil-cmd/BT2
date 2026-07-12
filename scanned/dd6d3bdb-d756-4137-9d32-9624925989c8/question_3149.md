# Q3149: CRC20 send_to_ibc burn backing under same-block reorder cross-phase equality

## Question
Can an unprivileged attacker enter through public send_to_ibc(string,uint) by controlling recipient, amount and caller token balance when two attacker-controlled transactions are valid separately but reordered in one block, then emit IBC send event not exactly matched by caller balance burn so that every bridge event equals the same caller balance and totalSupply burn fails and CheckTx, proposal verification, execution, export/import, and replay see the same message and state, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: contracts/src/ModuleCRC20.sol::send_to_ibc
- Entrypoint: public send_to_ibc(string,uint)
- Attacker controls: recipient, amount and caller token balance; scenario focus: same-block reorder plus cross-phase equality.
- Exploit idea: emit IBC send event not exactly matched by caller balance burn while two attacker-controlled transactions are valid separately but reordered in one block.
- Invariant to test: every bridge event equals the same caller balance and totalSupply burn; also verify CheckTx, proposal verification, execution, export/import, and replay see the same message and state.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: use a malicious minimal EVM contract or marshaled protobuf payload to exercise the entrypoint and inspect all state diffs. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
