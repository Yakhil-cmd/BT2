# Q2005: deploy_erc20_token() promise shape confusion in metadata deserialization into `Erc20Metadata`

## Question
Can an attacker make metadata deserialization into `Erc20Metadata` observe an unexpected promise count, result index, or result type through `deploy_erc20_token()` and its callback on the Aurora engine contract, so the wrong branch mints, refunds, or registers state and leads to Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/connector.rs::deploy_erc20_token / deploy_erc20_token_callback -> engine/src/engine.rs::deploy_erc20_token` -> `metadata deserialization into `Erc20Metadata``
- Entrypoint: `deploy_erc20_token()` and its callback on the Aurora engine contract
- Attacker controls: borsh `DeployErc20TokenArgs`, target NEP-141 account, metadata promise timing, callback invocation attempts, and repeated registration timing
- Exploit idea: target assumptions about promise shape and result indexing inside the named connector step.
- Invariant to test: NEP-141 to ERC-20 deployment must create exactly one canonical mirror with correct metadata and registration state
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Mock or simulate alternate promise-result layouts and assert the function rejects every malformed layout before mutating value-bearing state. write integration tests for both legacy and metadata-based deployment paths, including direct callback invocation attempts and duplicate registration attempts
