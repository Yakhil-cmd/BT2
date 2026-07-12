# Q3336: CRC21 evm-chain send burn under failed tail call event binding

## Question
Can an unprivileged attacker enter through external send_to_evm_chain(address,uint,uint,uint,bytes) by controlling recipient, amount, chain_id, bridge_fee, extraData and balance when a later bank, EVM, IBC, or callback step fails after earlier fund-sensitive work has run, then emit cross-chain event with amount plus fee not removed from sender so that principal plus fee equals token burn or lock before bridge processing fails and recognized EVM logs are accepted only when backed by the contract state transition that emitted them, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: contracts/src/ModuleCRC21.sol::send_to_evm_chain
- Entrypoint: external send_to_evm_chain(address,uint,uint,uint,bytes)
- Attacker controls: recipient, amount, chain_id, bridge_fee, extraData and balance; scenario focus: failed tail call plus event binding.
- Exploit idea: emit cross-chain event with amount plus fee not removed from sender while a later bank, EVM, IBC, or callback step fails after earlier fund-sensitive work has run.
- Invariant to test: principal plus fee equals token burn or lock before bridge processing; also verify recognized EVM logs are accepted only when backed by the contract state transition that emitted them.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: build a local integration test with two accounts and compare state root plus balances before and after the attempted flow. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
