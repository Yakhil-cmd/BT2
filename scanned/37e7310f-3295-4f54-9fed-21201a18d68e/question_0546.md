# Q546: PopTxs authorization binding drift

## Question
Can an unprivileged attacker reach `PopTxs` through JSON-RPC transaction submission or raw transaction ingestion using raw transaction bytes, tx type fields, calldata, signature material, and pool timing and make `PopTxs` bind execution to a signer, nonce, or payload different from the user intent, causing the invariant that one authorization must map to exactly one sender, one nonce consumption, and one executable payload to fail and leading to Unauthorized transaction?

## Target
- File/function: work/builder/builder.go:197 (PopTxs)
- Entrypoint: JSON-RPC transaction submission or raw transaction ingestion
- Attacker controls: raw transaction bytes, tx type fields, calldata, signature material, and pool timing
- Exploit idea: make `PopTxs` bind execution to a signer, nonce, or payload different from the user intent
- Invariant to test: one authorization must map to exactly one sender, one nonce consumption, and one executable payload
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: submit paired conflicting transactions on a local private network and diff recovered sender, consumed nonce, and executed calldata
