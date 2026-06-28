# Q1935: deploy_erc20_token() private or owner split at legacy-versus-metadata path selection in `DeployErc20TokenArgs`

## Question
Can an attacker exploit the 'private or owner' assumption around legacy-versus-metadata path selection in `DeployErc20TokenArgs` through `deploy_erc20_token()` and its callback on the Aurora engine contract, so a public call mimics an internal path and mutates protected configuration or value-bearing state, leading to Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::deploy_erc20_token / deploy_erc20_token_callback -> engine/src/engine.rs::deploy_erc20_token` -> `legacy-versus-metadata path selection in `DeployErc20TokenArgs``
- Entrypoint: `deploy_erc20_token()` and its callback on the Aurora engine contract
- Attacker controls: borsh `DeployErc20TokenArgs`, target NEP-141 account, metadata promise timing, callback invocation attempts, and repeated registration timing
- Exploit idea: test whether the targeted branch really distinguishes private callbacks from external calls in all cases.
- Invariant to test: NEP-141 to ERC-20 deployment must create exactly one canonical mirror with correct metadata and registration state
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Call the method from both the intended internal path and a direct external path and compare authorization behavior before any mutation. write integration tests for both legacy and metadata-based deployment paths, including direct callback invocation attempts and duplicate registration attempts
