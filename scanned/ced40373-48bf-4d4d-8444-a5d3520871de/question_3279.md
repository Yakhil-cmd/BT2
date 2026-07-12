# Q3279: CRC21 source send lock under ABI/protobuf edge cross-phase equality

## Question
Can an unprivileged attacker enter through public send_to_ibc(string,uint,uint,bytes) by controlling recipient, amount, channel_id, extraData, isSource and allowance when calldata, log data, topics, or protobuf bytes decode successfully but contain edge-case field encodings, then emit IBC send event for source token without exact module_address lock so that source sends lock exactly amount before native IBC transfer fails and CheckTx, proposal verification, execution, export/import, and replay see the same message and state, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: contracts/src/ModuleCRC21.sol::send_to_ibc
- Entrypoint: public send_to_ibc(string,uint,uint,bytes)
- Attacker controls: recipient, amount, channel_id, extraData, isSource and allowance; scenario focus: ABI/protobuf edge plus cross-phase equality.
- Exploit idea: emit IBC send event for source token without exact module_address lock while calldata, log data, topics, or protobuf bytes decode successfully but contain edge-case field encodings.
- Invariant to test: source sends lock exactly amount before native IBC transfer; also verify CheckTx, proposal verification, execution, export/import, and replay see the same message and state.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: use a malicious minimal EVM contract or marshaled protobuf payload to exercise the entrypoint and inspect all state diffs. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
