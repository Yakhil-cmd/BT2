# Q1638: send-to-IBC v2 topics under failed tail call rollback safety

## Question
Can an unprivileged attacker enter through EVM tx emitting __CronosSendToIbc v2 by controlling indexed sender topic, channel_id topic, recipient, amount and extraData when a later bank, EVM, IBC, or callback step fails after earlier fund-sensitive work has run, then misdecode indexed topics into another sender or channel so that topic-derived sender and channel match the Solidity state transition fails and failed callbacks, failed module calls, and failed packet flows leave no profitable residue, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/evmhandlers/send_to_ibc_v2.go::Handle
- Entrypoint: EVM tx emitting __CronosSendToIbc v2
- Attacker controls: indexed sender topic, channel_id topic, recipient, amount and extraData; scenario focus: failed tail call plus rollback safety.
- Exploit idea: misdecode indexed topics into another sender or channel while a later bank, EVM, IBC, or callback step fails after earlier fund-sensitive work has run.
- Invariant to test: topic-derived sender and channel match the Solidity state transition; also verify failed callbacks, failed module calls, and failed packet flows leave no profitable residue.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: replay the same transaction sequence from exported genesis and assert deterministic balances and mappings. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
