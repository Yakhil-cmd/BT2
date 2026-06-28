# Q1947: deploy_erc20_token() malformed JSON or borsh at metadata promise creation to `ft_metadata`

## Question
Can an attacker send malformed but parseable JSON or borsh through `deploy_erc20_token()` and its callback on the Aurora engine contract so that metadata promise creation to `ft_metadata` accepts a structurally valid payload with a semantically dangerous meaning, leading to Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::deploy_erc20_token / deploy_erc20_token_callback -> engine/src/engine.rs::deploy_erc20_token` -> `metadata promise creation to `ft_metadata``
- Entrypoint: `deploy_erc20_token()` and its callback on the Aurora engine contract
- Attacker controls: borsh `DeployErc20TokenArgs`, target NEP-141 account, metadata promise timing, callback invocation attempts, and repeated registration timing
- Exploit idea: look for edge-case decoding that preserves syntax but changes business meaning at the targeted step.
- Invariant to test: NEP-141 to ERC-20 deployment must create exactly one canonical mirror with correct metadata and registration state
- Expected Immunefi impact: Insolvency
- Fast validation: Fuzz the relevant JSON or borsh fields and assert downstream promise payloads and state changes remain semantically canonical. write integration tests for both legacy and metadata-based deployment paths, including direct callback invocation attempts and duplicate registration attempts
