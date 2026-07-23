# Q2974: getPendingNonce authorization binding drift

## Question
Can an unprivileged attacker reach `getPendingNonce` through JSON-RPC transaction submission or raw transaction ingestion using nonce, sender or fee-payer tuple, replacement timing, and raw transaction bytes and make `getPendingNonce` bind execution to a signer, nonce, or payload different from the user intent, causing the invariant that one authorization must map to exactly one sender, one nonce consumption, and one executable payload to fail and leading to Unauthorized transaction?

## Target
- File/function: blockchain/tx_pool.go:1992 (getPendingNonce)
- Entrypoint: JSON-RPC transaction submission or raw transaction ingestion
- Attacker controls: nonce, sender or fee-payer tuple, replacement timing, and raw transaction bytes
- Exploit idea: make `getPendingNonce` bind execution to a signer, nonce, or payload different from the user intent
- Invariant to test: one authorization must map to exactly one sender, one nonce consumption, and one executable payload
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: submit paired conflicting transactions on a local private network and diff recovered sender, consumed nonce, and executed calldata
