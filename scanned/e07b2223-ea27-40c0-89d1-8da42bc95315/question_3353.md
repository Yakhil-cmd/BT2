# Q3353: CRC21 evm-chain send burn under replay attempt backing conservation

## Question
Can an unprivileged attacker enter through external send_to_evm_chain(address,uint,uint,uint,bytes) by controlling recipient, amount, chain_id, bridge_fee, extraData and balance when the attacker repeats a previously successful or failed packet, tx, event, or callback, then emit cross-chain event with amount plus fee not removed from sender so that principal plus fee equals token burn or lock before bridge processing fails and escrowed, burned, minted, locked, and released amounts conserve value exactly, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: contracts/src/ModuleCRC21.sol::send_to_evm_chain
- Entrypoint: external send_to_evm_chain(address,uint,uint,uint,bytes)
- Attacker controls: recipient, amount, chain_id, bridge_fee, extraData and balance; scenario focus: replay attempt plus backing conservation.
- Exploit idea: emit cross-chain event with amount plus fee not removed from sender while the attacker repeats a previously successful or failed packet, tx, event, or callback.
- Invariant to test: principal plus fee equals token burn or lock before bridge processing; also verify escrowed, burned, minted, locked, and released amounts conserve value exactly.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: replay the same transaction sequence from exported genesis and assert deterministic balances and mappings. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
