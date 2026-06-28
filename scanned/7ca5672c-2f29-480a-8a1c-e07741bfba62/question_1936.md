# Q1936: deploy_erc20_token() queue or promise stranding at legacy-versus-metadata path selection in `DeployErc20TokenArgs`

## Question
Can an attacker make legacy-versus-metadata path selection in `DeployErc20TokenArgs` enqueue a downstream action that can no longer complete or be retried safely, leaving user funds or bridge state stranded and causing Insolvency?

## Target
- File/function: `engine/src/contract_methods/connector.rs::deploy_erc20_token / deploy_erc20_token_callback -> engine/src/engine.rs::deploy_erc20_token` -> `legacy-versus-metadata path selection in `DeployErc20TokenArgs``
- Entrypoint: `deploy_erc20_token()` and its callback on the Aurora engine contract
- Attacker controls: borsh `DeployErc20TokenArgs`, target NEP-141 account, metadata promise timing, callback invocation attempts, and repeated registration timing
- Exploit idea: target the safe-completion assumptions of the promise created by the named step.
- Invariant to test: NEP-141 to ERC-20 deployment must create exactly one canonical mirror with correct metadata and registration state
- Expected Immunefi impact: Insolvency
- Fast validation: Interrupt the downstream action at different stages and assert no user value remains trapped without a valid retry or refund path. write integration tests for both legacy and metadata-based deployment paths, including direct callback invocation attempts and duplicate registration attempts
