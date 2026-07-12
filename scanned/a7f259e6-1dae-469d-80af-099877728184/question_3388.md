# Q3388: CRC21 evm-chain send burn under remap window rollback safety

## Question
Can an unprivileged attacker enter through external send_to_evm_chain(address,uint,uint,uint,bytes) by controlling recipient, amount, chain_id, bridge_fee, extraData and balance when token mappings, params, permissions, or packet state change between check, execution, callback, or acknowledgement, then emit cross-chain event with amount plus fee not removed from sender so that principal plus fee equals token burn or lock before bridge processing fails and failed callbacks, failed module calls, and failed packet flows leave no profitable residue, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: contracts/src/ModuleCRC21.sol::send_to_evm_chain
- Entrypoint: external send_to_evm_chain(address,uint,uint,uint,bytes)
- Attacker controls: recipient, amount, chain_id, bridge_fee, extraData and balance; scenario focus: remap window plus rollback safety.
- Exploit idea: emit cross-chain event with amount plus fee not removed from sender while token mappings, params, permissions, or packet state change between check, execution, callback, or acknowledgement.
- Invariant to test: principal plus fee equals token burn or lock before bridge processing; also verify failed callbacks, failed module calls, and failed packet flows leave no profitable residue.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: replay the same transaction sequence from exported genesis and assert deterministic balances and mappings. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
