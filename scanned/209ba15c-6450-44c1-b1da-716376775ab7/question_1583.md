# Q1583: DecodeAnchoringDataToJSON authorization binding drift

## Question
Can an unprivileged attacker reach `DecodeAnchoringDataToJSON` through JSON-RPC transaction submission or raw transaction ingestion using raw transaction bytes, tx type fields, calldata, signature material, and pool timing and make `DecodeAnchoringDataToJSON` bind execution to a signer, nonce, or payload different from the user intent, causing the invariant that one authorization must map to exactly one sender, one nonce consumption, and one executable payload to fail and leading to Unauthorized transaction?

## Target
- File/function: blockchain/types/anchoring_data.go:134 (DecodeAnchoringDataToJSON)
- Entrypoint: JSON-RPC transaction submission or raw transaction ingestion
- Attacker controls: raw transaction bytes, tx type fields, calldata, signature material, and pool timing
- Exploit idea: make `DecodeAnchoringDataToJSON` bind execution to a signer, nonce, or payload different from the user intent
- Invariant to test: one authorization must map to exactly one sender, one nonce consumption, and one executable payload
- Expected Immunefi impact: Unauthorized transaction
- Fast validation: submit paired conflicting transactions on a local private network and diff recovered sender, consumed nonce, and executed calldata
