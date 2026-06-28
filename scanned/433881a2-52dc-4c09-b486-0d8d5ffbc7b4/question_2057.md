# Q2057: deploy_erc20_token() connector target confusion in registration in `register_token`

## Question
Can an attacker route registration in `register_token` toward the wrong connector account or downstream method through `deploy_erc20_token()` and its callback on the Aurora engine contract, so a valid-looking request lands in the wrong contract context and causes Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::deploy_erc20_token / deploy_erc20_token_callback -> engine/src/engine.rs::deploy_erc20_token` -> `registration in `register_token``
- Entrypoint: `deploy_erc20_token()` and its callback on the Aurora engine contract
- Attacker controls: borsh `DeployErc20TokenArgs`, target NEP-141 account, metadata promise timing, callback invocation attempts, and repeated registration timing
- Exploit idea: abuse connector account selection and method-name routing near the targeted helper.
- Invariant to test: NEP-141 to ERC-20 deployment must create exactly one canonical mirror with correct metadata and registration state
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Inspect the generated promise target account and method for crafted inputs and assert they always match the intended operation. write integration tests for both legacy and metadata-based deployment paths, including direct callback invocation attempts and duplicate registration attempts
