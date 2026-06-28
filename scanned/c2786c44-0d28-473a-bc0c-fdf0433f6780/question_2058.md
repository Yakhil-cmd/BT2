# Q2058: deploy_erc20_token() revert/success split after registration in `register_token`

## Question
Can an attacker make registration in `register_token` treat a downstream revert as success, or a downstream success as failure, so mint, refund, or registration logic goes down the wrong branch and leads to Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::deploy_erc20_token / deploy_erc20_token_callback -> engine/src/engine.rs::deploy_erc20_token` -> `registration in `register_token``
- Entrypoint: `deploy_erc20_token()` and its callback on the Aurora engine contract
- Attacker controls: borsh `DeployErc20TokenArgs`, target NEP-141 account, metadata promise timing, callback invocation attempts, and repeated registration timing
- Exploit idea: attack success detection and branch selection around the targeted callback or promise result.
- Invariant to test: NEP-141 to ERC-20 deployment must create exactly one canonical mirror with correct metadata and registration state
- Expected Immunefi impact: Insolvency
- Fast validation: Simulate both success and failure promise outcomes and assert the chosen branch matches the real downstream result every time. write integration tests for both legacy and metadata-based deployment paths, including direct callback invocation attempts and duplicate registration attempts
