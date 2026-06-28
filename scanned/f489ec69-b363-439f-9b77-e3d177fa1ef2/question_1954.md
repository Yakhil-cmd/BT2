# Q1954: deploy_erc20_token() cross-asset mixup in metadata promise creation to `ft_metadata`

## Question
Can an attacker use `deploy_erc20_token()` and its callback on the Aurora engine contract to make metadata promise creation to `ft_metadata` associate the wrong token contract, metadata, or bridge account with the current action, so one asset is credited or debited as another and causes Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::deploy_erc20_token / deploy_erc20_token_callback -> engine/src/engine.rs::deploy_erc20_token` -> `metadata promise creation to `ft_metadata``
- Entrypoint: `deploy_erc20_token()` and its callback on the Aurora engine contract
- Attacker controls: borsh `DeployErc20TokenArgs`, target NEP-141 account, metadata promise timing, callback invocation attempts, and repeated registration timing
- Exploit idea: abuse asset-identity assumptions at the targeted mapping or metadata step.
- Invariant to test: NEP-141 to ERC-20 deployment must create exactly one canonical mirror with correct metadata and registration state
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Exercise different token identities around the same flow and assert each path touches only its own balances and metadata. write integration tests for both legacy and metadata-based deployment paths, including direct callback invocation attempts and duplicate registration attempts
