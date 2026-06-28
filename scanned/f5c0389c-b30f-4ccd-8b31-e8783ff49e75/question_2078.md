# Q2078: deploy_erc20_token() revert/success split after address return encoding after deployment

## Question
Can an attacker make address return encoding after deployment treat a downstream revert as success, or a downstream success as failure, so mint, refund, or registration logic goes down the wrong branch and leads to Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/connector.rs::deploy_erc20_token / deploy_erc20_token_callback -> engine/src/engine.rs::deploy_erc20_token` -> `address return encoding after deployment`
- Entrypoint: `deploy_erc20_token()` and its callback on the Aurora engine contract
- Attacker controls: borsh `DeployErc20TokenArgs`, target NEP-141 account, metadata promise timing, callback invocation attempts, and repeated registration timing
- Exploit idea: attack success detection and branch selection around the targeted callback or promise result.
- Invariant to test: NEP-141 to ERC-20 deployment must create exactly one canonical mirror with correct metadata and registration state
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Simulate both success and failure promise outcomes and assert the chosen branch matches the real downstream result every time. write integration tests for both legacy and metadata-based deployment paths, including direct callback invocation attempts and duplicate registration attempts
