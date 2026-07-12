# Q0403: CRC21-to-native release under amount boundary backing conservation

## Question
Can an unprivileged attacker enter through EVM hook from a mapped CRC21 or proxy contract by controlling contract, receiver, amount and module method result when the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid, then release native coins while token burn or lock fails or differs so that native release and CRC21 burn/lock are atomic and equal fails and escrowed, burned, minted, locked, and released amounts conserve value exactly, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/evm.go::ConvertCoinFromCRC21ToNative
- Entrypoint: EVM hook from a mapped CRC21 or proxy contract
- Attacker controls: contract, receiver, amount and module method result; scenario focus: amount boundary plus backing conservation.
- Exploit idea: release native coins while token burn or lock fails or differs while the attacker uses smallest, dust, and near-limit amounts that remain syntactically valid.
- Invariant to test: native release and CRC21 burn/lock are atomic and equal; also verify escrowed, burned, minted, locked, and released amounts conserve value exactly.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: replay the same transaction sequence from exported genesis and assert deterministic balances and mappings. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
