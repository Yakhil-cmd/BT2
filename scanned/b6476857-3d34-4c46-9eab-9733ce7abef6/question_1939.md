# Q1939: deploy_erc20_token() silo bypass through legacy-versus-metadata path selection in `DeployErc20TokenArgs`

## Question
Can an attacker use `deploy_erc20_token()` and its callback on the Aurora engine contract so that legacy-versus-metadata path selection in `DeployErc20TokenArgs` reaches token receive, submit, deploy, or mirror behavior that silo mode was supposed to block, resulting in Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::deploy_erc20_token / deploy_erc20_token_callback -> engine/src/engine.rs::deploy_erc20_token` -> `legacy-versus-metadata path selection in `DeployErc20TokenArgs``
- Entrypoint: `deploy_erc20_token()` and its callback on the Aurora engine contract
- Attacker controls: borsh `DeployErc20TokenArgs`, target NEP-141 account, metadata promise timing, callback invocation attempts, and repeated registration timing
- Exploit idea: find a public path around the targeted silo-related check.
- Invariant to test: NEP-141 to ERC-20 deployment must create exactly one canonical mirror with correct metadata and registration state
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Enable silo restrictions in state and verify every alternate public path still rejects the same blocked action. write integration tests for both legacy and metadata-based deployment paths, including direct callback invocation attempts and duplicate registration attempts
