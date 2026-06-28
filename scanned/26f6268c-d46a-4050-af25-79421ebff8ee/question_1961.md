# Q1961: deploy_erc20_token() serialization split around private-call enforcement in `deploy_erc20_token_callback`

## Question
Can an unprivileged attacker use `deploy_erc20_token()` and its callback on the Aurora engine contract with borsh `DeployErc20TokenArgs`, target NEP-141 account, metadata promise timing, callback invocation attempts, and repeated registration timing and make private-call enforcement in `deploy_erc20_token_callback` serialize one recipient, amount, or account identity while the downstream promise or engine path interprets another, leading to Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::deploy_erc20_token / deploy_erc20_token_callback -> engine/src/engine.rs::deploy_erc20_token` -> `private-call enforcement in `deploy_erc20_token_callback``
- Entrypoint: `deploy_erc20_token()` and its callback on the Aurora engine contract
- Attacker controls: borsh `DeployErc20TokenArgs`, target NEP-141 account, metadata promise timing, callback invocation attempts, and repeated registration timing
- Exploit idea: abuse a serialization boundary at the targeted step to split what the user intended from what the downstream connector sees.
- Invariant to test: NEP-141 to ERC-20 deployment must create exactly one canonical mirror with correct metadata and registration state
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Inspect the exact promise payload or downstream calldata created from the crafted input and compare it with the original user intent. write integration tests for both legacy and metadata-based deployment paths, including direct callback invocation attempts and duplicate registration attempts
