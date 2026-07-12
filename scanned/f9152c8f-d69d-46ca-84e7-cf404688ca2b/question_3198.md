# Q3198: CRC20 send_to_ibc burn backing under nested execution rollback safety

## Question
Can an unprivileged attacker enter through public send_to_ibc(string,uint) by controlling recipient, amount and caller token balance when a native action, precompile, or module EVM call triggers another hook, callback, or state transition, then emit IBC send event not exactly matched by caller balance burn so that every bridge event equals the same caller balance and totalSupply burn fails and failed callbacks, failed module calls, and failed packet flows leave no profitable residue, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: contracts/src/ModuleCRC20.sol::send_to_ibc
- Entrypoint: public send_to_ibc(string,uint)
- Attacker controls: recipient, amount and caller token balance; scenario focus: nested execution plus rollback safety.
- Exploit idea: emit IBC send event not exactly matched by caller balance burn while a native action, precompile, or module EVM call triggers another hook, callback, or state transition.
- Invariant to test: every bridge event equals the same caller balance and totalSupply burn; also verify failed callbacks, failed module calls, and failed packet flows leave no profitable residue.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: replay the same transaction sequence from exported genesis and assert deterministic balances and mappings. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
