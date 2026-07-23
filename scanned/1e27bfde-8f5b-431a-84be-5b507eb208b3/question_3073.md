# Q3073: CheckNonce authorization binding drift

## Question
Can an unprivileged attacker reach `CheckNonce` through JSON-RPC transaction submission or raw transaction ingestion using nonce, sender or fee-payer tuple, replacement timing, and raw transaction bytes and make `CheckNonce` bind execution to a signer, nonce, or payload different from the user intent, causing the invariant that one authorization must map to exactly one sender, one nonce consumption, and one executable payload to fail and leading to Unauthorized transaction?

## Target
- File/function: blockchain/types/transaction.go:469 (CheckNonce)
- Entrypoint: JSON-RPC transaction submission or raw transaction ingestion
- Attacker controls: nonce, sender or fee-payer tuple, replacement timing, and raw transaction bytes
- Exploit idea: make `CheckNonce` bind execution to a signer, nonce, or payload different from the user intent
- Invariant to test: one authorization must map to exactly one sender, one nonce consumption, and one executable payload
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: submit paired conflicting transactions on a local private network and diff recovered sender, consumed nonce, and executed calldata
