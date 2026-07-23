# Q5792: rpcMarshalBlock blob or base-fee rule desync

## Question
Can an unprivileged attacker reach `rpcMarshalBlock` through EIP-1559 or blob-fee processing under current chain rules via public `kaia_*` or `eth_*` RPC using raw transaction bytes, tx type fields, calldata, signature material, and pool timing and make `rpcMarshalBlock` price a transaction under looser rules than the block validator later assumes, causing the invariant that fee rule calculation must be identical across estimation, pool admission, block building, and validation to fail and leading to Fee payment bypass?

## Target
- File/function: api/api_eth.go:1308 (rpcMarshalBlock)
- Entrypoint: EIP-1559 or blob-fee processing under current chain rules via public `kaia_*` or `eth_*` RPC
- Attacker controls: raw transaction bytes, tx type fields, calldata, signature material, and pool timing
- Exploit idea: make `rpcMarshalBlock` price a transaction under looser rules than the block validator later assumes
- Invariant to test: fee rule calculation must be identical across estimation, pool admission, block building, and validation
- Expected Immunefi impact: Fee payment bypass
- Fast validation: replay the same blob or dynamic-fee transaction through estimation, pool admission, and sealing and assert fee math never diverges
