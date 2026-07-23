# Q5791: rpcMarshalHeader blob or base-fee rule desync

## Question
Can an unprivileged attacker reach `rpcMarshalHeader` through EIP-1559 or blob-fee processing under current chain rules via public `kaia_*` or `eth_*` RPC using raw transaction bytes, tx type fields, calldata, signature material, and pool timing and make `rpcMarshalHeader` price a transaction under looser rules than the block validator later assumes, causing the invariant that fee rule calculation must be identical across estimation, pool admission, block building, and validation to fail and leading to Fee payment bypass?

## Target
- File/function: api/api_eth.go:1303 (rpcMarshalHeader)
- Entrypoint: EIP-1559 or blob-fee processing under current chain rules via public `kaia_*` or `eth_*` RPC
- Attacker controls: raw transaction bytes, tx type fields, calldata, signature material, and pool timing
- Exploit idea: make `rpcMarshalHeader` price a transaction under looser rules than the block validator later assumes
- Invariant to test: fee rule calculation must be identical across estimation, pool admission, block building, and validation
- Expected Immunefi impact: Fee payment bypass
- Fast validation: replay the same blob or dynamic-fee transaction through estimation, pool admission, and sealing and assert fee math never diverges
