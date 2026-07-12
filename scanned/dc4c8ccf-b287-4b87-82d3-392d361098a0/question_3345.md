# Q3345: CRC21 evm-chain send burn under same-block reorder channel provenance

## Question
Can an unprivileged attacker enter through external send_to_evm_chain(address,uint,uint,uint,bytes) by controlling recipient, amount, chain_id, bridge_fee, extraData and balance when two attacker-controlled transactions are valid separately but reordered in one block, then emit cross-chain event with amount plus fee not removed from sender so that principal plus fee equals token burn or lock before bridge processing fails and IBC channel, packet, and denom trace identity cannot be attacker-selected or replayed, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: contracts/src/ModuleCRC21.sol::send_to_evm_chain
- Entrypoint: external send_to_evm_chain(address,uint,uint,uint,bytes)
- Attacker controls: recipient, amount, chain_id, bridge_fee, extraData and balance; scenario focus: same-block reorder plus channel provenance.
- Exploit idea: emit cross-chain event with amount plus fee not removed from sender while two attacker-controlled transactions are valid separately but reordered in one block.
- Invariant to test: principal plus fee equals token burn or lock before bridge processing; also verify IBC channel, packet, and denom trace identity cannot be attacker-selected or replayed.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: write a focused unit test around the named function and assert pre/post bank, module, and contract balances. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
