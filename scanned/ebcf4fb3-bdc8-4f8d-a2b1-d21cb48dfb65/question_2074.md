# Q2074: deploy_erc20_token() cross-asset mixup in address return encoding after deployment

## Question
Can an attacker use `deploy_erc20_token()` and its callback on the Aurora engine contract to make address return encoding after deployment associate the wrong token contract, metadata, or bridge account with the current action, so one asset is credited or debited as another and causes Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/connector.rs::deploy_erc20_token / deploy_erc20_token_callback -> engine/src/engine.rs::deploy_erc20_token` -> `address return encoding after deployment`
- Entrypoint: `deploy_erc20_token()` and its callback on the Aurora engine contract
- Attacker controls: borsh `DeployErc20TokenArgs`, target NEP-141 account, metadata promise timing, callback invocation attempts, and repeated registration timing
- Exploit idea: abuse asset-identity assumptions at the targeted mapping or metadata step.
- Invariant to test: NEP-141 to ERC-20 deployment must create exactly one canonical mirror with correct metadata and registration state
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Exercise different token identities around the same flow and assert each path touches only its own balances and metadata. write integration tests for both legacy and metadata-based deployment paths, including direct callback invocation attempts and duplicate registration attempts
