# Q1929: deploy_erc20_token() recipient mismatch in legacy-versus-metadata path selection in `DeployErc20TokenArgs`

## Question
Can an attacker make legacy-versus-metadata path selection in `DeployErc20TokenArgs` route value to a different recipient than the one visible at the public entrypoint, via encoding, truncation, or mapping confusion, causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/connector.rs::deploy_erc20_token / deploy_erc20_token_callback -> engine/src/engine.rs::deploy_erc20_token` -> `legacy-versus-metadata path selection in `DeployErc20TokenArgs``
- Entrypoint: `deploy_erc20_token()` and its callback on the Aurora engine contract
- Attacker controls: borsh `DeployErc20TokenArgs`, target NEP-141 account, metadata promise timing, callback invocation attempts, and repeated registration timing
- Exploit idea: exploit a mismatch between public recipient intent and downstream recipient bytes or addresses.
- Invariant to test: NEP-141 to ERC-20 deployment must create exactly one canonical mirror with correct metadata and registration state
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Use crafted recipient values and compare the entrypoint-visible recipient with the recipient encoded in downstream calls or minted balances. write integration tests for both legacy and metadata-based deployment paths, including direct callback invocation attempts and duplicate registration attempts
