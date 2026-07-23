# Q228: IsLegacyTransaction authorization binding drift

## Question
Can an unprivileged attacker reach `IsLegacyTransaction` through JSON-RPC transaction submission or raw transaction ingestion using raw transaction bytes, tx type fields, calldata, signature material, and pool timing and make `IsLegacyTransaction` bind execution to a signer, nonce, or payload different from the user intent, causing the invariant that one authorization must map to exactly one sender, one nonce consumption, and one executable payload to fail and leading to Unauthorized transaction?

## Target
- File/function: blockchain/types/tx_internal_data.go:273 (IsLegacyTransaction)
- Entrypoint: JSON-RPC transaction submission or raw transaction ingestion
- Attacker controls: raw transaction bytes, tx type fields, calldata, signature material, and pool timing
- Exploit idea: make `IsLegacyTransaction` bind execution to a signer, nonce, or payload different from the user intent
- Invariant to test: one authorization must map to exactly one sender, one nonce consumption, and one executable payload
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: submit paired conflicting transactions on a local private network and diff recovered sender, consumed nonce, and executed calldata
