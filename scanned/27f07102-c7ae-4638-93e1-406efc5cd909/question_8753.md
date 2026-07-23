# Q8753: getNonce blob or base-fee rule desync

## Question
Can an unprivileged attacker reach `getNonce` through EIP-1559 or blob-fee processing under current chain rules using nonce, sender or fee-payer tuple, replacement timing, and raw transaction bytes and make `getNonce` price a transaction under looser rules than the block validator later assumes, causing the invariant that fee rule calculation must be identical across estimation, pool admission, block building, and validation to fail and leading to Fee payment bypass?

## Target
- File/function: blockchain/tx_pool.go:1973 (getNonce)
- Entrypoint: EIP-1559 or blob-fee processing under current chain rules
- Attacker controls: nonce, sender or fee-payer tuple, replacement timing, and raw transaction bytes
- Exploit idea: make `getNonce` price a transaction under looser rules than the block validator later assumes
- Invariant to test: fee rule calculation must be identical across estimation, pool admission, block building, and validation
- Expected Immunefi impact: Fee payment bypass
- Fast validation: replay the same blob or dynamic-fee transaction through estimation, pool admission, and sealing and assert fee math never diverges
