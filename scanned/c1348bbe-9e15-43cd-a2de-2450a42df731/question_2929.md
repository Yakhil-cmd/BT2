# Q2929: nonce authorization binding drift

## Question
Can an unprivileged attacker reach `nonce` through JSON-RPC transaction submission or raw transaction ingestion via public `kaia_*` or `eth_*` RPC using nonce, sender or fee-payer tuple, replacement timing, and raw transaction bytes and make `nonce` bind execution to a signer, nonce, or payload different from the user intent, causing the invariant that one authorization must map to exactly one sender, one nonce consumption, and one executable payload to fail and leading to Unauthorized transaction?

## Target
- File/function: api/tx_args.go:390 (nonce)
- Entrypoint: JSON-RPC transaction submission or raw transaction ingestion via public `kaia_*` or `eth_*` RPC
- Attacker controls: nonce, sender or fee-payer tuple, replacement timing, and raw transaction bytes
- Exploit idea: make `nonce` bind execution to a signer, nonce, or payload different from the user intent
- Invariant to test: one authorization must map to exactly one sender, one nonce consumption, and one executable payload
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: submit paired conflicting transactions on a local private network and diff recovered sender, consumed nonce, and executed calldata
