# Q1356: contract code mapping check under replay attempt event binding

## Question
Can an unprivileged attacker enter through MsgUpdateTokenMapping by controlling contract account code, precompile-range address and ABI support when the attacker repeats a previously successful or failed packet, tx, event, or callback, then map code that exists but cannot safely implement CRC21 module methods so that mapped contracts must support required burn, mint and transfer module calls fails and recognized EVM logs are accepted only when backed by the contract state transition that emitted them, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/keeper.go::ensureContractCode
- Entrypoint: MsgUpdateTokenMapping
- Attacker controls: contract account code, precompile-range address and ABI support; scenario focus: replay attempt plus event binding.
- Exploit idea: map code that exists but cannot safely implement CRC21 module methods while the attacker repeats a previously successful or failed packet, tx, event, or callback.
- Invariant to test: mapped contracts must support required burn, mint and transfer module calls; also verify recognized EVM logs are accepted only when backed by the contract state transition that emitted them.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: build a local integration test with two accounts and compare state root plus balances before and after the attempted flow. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
