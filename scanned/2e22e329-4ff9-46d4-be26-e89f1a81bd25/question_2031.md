# Q2031: deploy_erc20_token() idempotence break at bytecode construction in `setup_deploy_erc20_input`

## Question
Can an attacker repeat the exact same public request through `deploy_erc20_token()` and its callback on the Aurora engine contract and make bytecode construction in `setup_deploy_erc20_input` treat it as fresh instead of already-consumed state, leading to Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::deploy_erc20_token / deploy_erc20_token_callback -> engine/src/engine.rs::deploy_erc20_token` -> `bytecode construction in `setup_deploy_erc20_input``
- Entrypoint: `deploy_erc20_token()` and its callback on the Aurora engine contract
- Attacker controls: borsh `DeployErc20TokenArgs`, target NEP-141 account, metadata promise timing, callback invocation attempts, and repeated registration timing
- Exploit idea: look for missing idempotence or replay resistance at the targeted connector step.
- Invariant to test: NEP-141 to ERC-20 deployment must create exactly one canonical mirror with correct metadata and registration state
- Expected Immunefi impact: Insolvency
- Fast validation: Replay the same request and assert supply, storage registration, and mappings do not move on the second attempt. write integration tests for both legacy and metadata-based deployment paths, including direct callback invocation attempts and duplicate registration attempts
