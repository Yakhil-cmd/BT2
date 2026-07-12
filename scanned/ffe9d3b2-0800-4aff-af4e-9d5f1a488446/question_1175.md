# Q1175: external mapping deletion fallback under ABI/protobuf edge channel provenance

## Question
Can an unprivileged attacker enter through MsgUpdateTokenMapping deleting a mapping by controlling denom with external and auto mappings plus reverse key when calldata, log data, topics, or protobuf bytes decode successfully but contain edge-case field encodings, then delete an external mapping so fallback auto mapping redirects valuable withdrawals so that mapping deletion cannot rebind a denom to attacker-controlled code fails and IBC channel, packet, and denom trace identity cannot be attacker-selected or replayed, leading to Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code?

## Target
- File/function: x/cronos/keeper/keeper.go::DeleteExternalContractForDenom
- Entrypoint: MsgUpdateTokenMapping deleting a mapping
- Attacker controls: denom with external and auto mappings plus reverse key; scenario focus: ABI/protobuf edge plus channel provenance.
- Exploit idea: delete an external mapping so fallback auto mapping redirects valuable withdrawals while calldata, log data, topics, or protobuf bytes decode successfully but contain edge-case field encodings.
- Invariant to test: mapping deletion cannot rebind a denom to attacker-controlled code; also verify IBC channel, packet, and denom trace identity cannot be attacker-selected or replayed.
- Expected Immunefi impact: Critical - direct unintentional withdrawal, draining, or loss of user funds through Cronos blockchain/app code.
- Fast validation: write a focused unit test around the named function and assert pre/post bank, module, and contract balances. Scoped to live HackenProof Cronos Blockchain Protocols: cryptographic flaws and vulnerabilities causing unintentional withdrawal, draining, or loss of user funds; excludes DoS/DDoS/spam, gas draining, leaked keys, privileged-address/admin abuse, basic governance attacks, known fork/dependency issues without a working Cronos PoC, tests, mocks, scripts, docs, disabled configs, and non-production code.
