# Q3403: CRC20 proxy authority under amount boundary backing conservation

## Question
Can an unprivileged attacker enter through DSToken authority check used by ModuleCRC20Proxy by controlling src, dst, sig and proxyAddress constructor value when the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid, then grant token movement authority beyond the intended proxy path so that only configured proxy can move/burn/mint backing tokens for bridge flows fails and escrowed, burned, minted, locked, and released amounts conserve value exactly, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: contracts/src/ModuleCRC20ProxyAuthority.sol::canCall
- Entrypoint: DSToken authority check used by ModuleCRC20Proxy
- Attacker controls: src, dst, sig and proxyAddress constructor value; scenario focus: amount boundary plus backing conservation.
- Exploit idea: grant token movement authority beyond the intended proxy path while the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid.
- Invariant to test: only configured proxy can move/burn/mint backing tokens for bridge flows; also verify escrowed, burned, minted, locked, and released amounts conserve value exactly.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: replay the same transaction sequence from exported genesis and assert deterministic balances and mappings. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
