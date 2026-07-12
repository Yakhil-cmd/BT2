# Q0451: CRC21-to-native release under replay attempt atomicity

## Question
Can an unprivileged attacker enter through EVM hook from a mapped CRC21 or proxy contract by controlling contract, receiver, amount and module method result when the attacker repeats a previously successful or failed packet, tx, event, or callback, then release native coins while token burn or lock fails or differs so that native release and CRC21 burn/lock are atomic and equal fails and no partial native, EVM, IBC, or token state can commit on an error path, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/evm.go::ConvertCoinFromCRC21ToNative
- Entrypoint: EVM hook from a mapped CRC21 or proxy contract
- Attacker controls: contract, receiver, amount and module method result; scenario focus: replay attempt plus atomicity.
- Exploit idea: release native coins while token burn or lock fails or differs while the attacker repeats a previously successful or failed packet, tx, event, or callback.
- Invariant to test: native release and CRC21 burn/lock are atomic and equal; also verify no partial native, EVM, IBC, or token state can commit on an error path.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: build a local integration test with two accounts and compare state root plus balances before and after the attempted flow. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
