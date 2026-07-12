# Q3416: CRC20 proxy authority under duplicate ordering event binding

## Question
Can an unprivileged attacker enter through DSToken authority check used by ModuleCRC20Proxy by controlling src, dst, sig and proxyAddress constructor value when the attacker repeats or reorders value-bearing items inside one transaction or receipt, then grant token movement authority beyond the intended proxy path so that only configured proxy can move/burn/mint backing tokens for bridge flows fails and recognized EVM logs are accepted only when backed by the contract state transition that emitted them, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: contracts/src/ModuleCRC20ProxyAuthority.sol::canCall
- Entrypoint: DSToken authority check used by ModuleCRC20Proxy
- Attacker controls: src, dst, sig and proxyAddress constructor value; scenario focus: duplicate ordering plus event binding.
- Exploit idea: grant token movement authority beyond the intended proxy path while the attacker repeats or reorders value-bearing items inside one transaction or receipt.
- Invariant to test: only configured proxy can move/burn/mint backing tokens for bridge flows; also verify recognized EVM logs are accepted only when backed by the contract state transition that emitted them.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: build a local integration test with two accounts and compare state root plus balances before and after the attempted flow. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
