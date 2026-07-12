# Q1596: send-to-IBC v1 sender binding under nested execution event binding

## Question
Can an unprivileged attacker enter through EVM tx emitting __CronosSendToIbc v1 by controlling sender in log data, recipient string, amount and mapped contract when a native action, precompile, or module EVM call triggers another hook, callback, or state transition, then make the hook transfer or refund for a sender that did not burn or lock tokens so that log sender is authenticated to the economic token owner fails and recognized EVM logs are accepted only when backed by the contract state transition that emitted them, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/evmhandlers/send_to_ibc.go::Handle
- Entrypoint: EVM tx emitting __CronosSendToIbc v1
- Attacker controls: sender in log data, recipient string, amount and mapped contract; scenario focus: nested execution plus event binding.
- Exploit idea: make the hook transfer or refund for a sender that did not burn or lock tokens while a native action, precompile, or module EVM call triggers another hook, callback, or state transition.
- Invariant to test: log sender is authenticated to the economic token owner; also verify recognized EVM logs are accepted only when backed by the contract state transition that emitted them.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: build a local integration test with two accounts and compare state root plus balances before and after the attempted flow. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
