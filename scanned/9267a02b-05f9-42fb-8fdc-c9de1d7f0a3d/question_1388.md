# Q1388: contract code mapping check under remap window rollback safety

## Question
Can an unprivileged attacker enter through MsgUpdateTokenMapping by controlling contract account code, precompile-range address and ABI support when token mappings, params, permissions, or packet state change between check, execution, callback, or acknowledgement, then map code that exists but cannot safely implement CRC21 module methods so that mapped contracts must support required burn, mint and transfer module calls fails and failed callbacks, failed module calls, and failed packet flows leave no profitable residue, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/keeper.go::ensureContractCode
- Entrypoint: MsgUpdateTokenMapping
- Attacker controls: contract account code, precompile-range address and ABI support; scenario focus: remap window plus rollback safety.
- Exploit idea: map code that exists but cannot safely implement CRC21 module methods while token mappings, params, permissions, or packet state change between check, execution, callback, or acknowledgement.
- Invariant to test: mapped contracts must support required burn, mint and transfer module calls; also verify failed callbacks, failed module calls, and failed packet flows leave no profitable residue.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: replay the same transaction sequence from exported genesis and assert deterministic balances and mappings. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
