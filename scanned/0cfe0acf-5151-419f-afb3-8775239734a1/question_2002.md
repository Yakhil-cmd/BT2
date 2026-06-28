# Q2002: deploy_erc20_token() double-apply path at metadata deserialization into `Erc20Metadata`

## Question
Can an attacker trigger metadata deserialization into `Erc20Metadata` twice for one logical action through retries, repeated calls, or callback reuse from `deploy_erc20_token()` and its callback on the Aurora engine contract, so burn, mint, refund, or registration state is applied more than once and causes Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::deploy_erc20_token / deploy_erc20_token_callback -> engine/src/engine.rs::deploy_erc20_token` -> `metadata deserialization into `Erc20Metadata``
- Entrypoint: `deploy_erc20_token()` and its callback on the Aurora engine contract
- Attacker controls: borsh `DeployErc20TokenArgs`, target NEP-141 account, metadata promise timing, callback invocation attempts, and repeated registration timing
- Exploit idea: look for a one-to-many application of one user action around the targeted connector step.
- Invariant to test: NEP-141 to ERC-20 deployment must create exactly one canonical mirror with correct metadata and registration state
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Replay the same logical action across repeated calls and callback timing variations and assert supply, mappings, and balances remain single-applied. write integration tests for both legacy and metadata-based deployment paths, including direct callback invocation attempts and duplicate registration attempts
