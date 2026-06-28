# Q1964: deploy_erc20_token() callback spoof around private-call enforcement in `deploy_erc20_token_callback`

## Question
Can an attacker directly invoke or spoof the async context expected by private-call enforcement in `deploy_erc20_token_callback` through `deploy_erc20_token()` and its callback on the Aurora engine contract so a callback-only step runs with attacker-controlled bytes and causes Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::deploy_erc20_token / deploy_erc20_token_callback -> engine/src/engine.rs::deploy_erc20_token` -> `private-call enforcement in `deploy_erc20_token_callback``
- Entrypoint: `deploy_erc20_token()` and its callback on the Aurora engine contract
- Attacker controls: borsh `DeployErc20TokenArgs`, target NEP-141 account, metadata promise timing, callback invocation attempts, and repeated registration timing
- Exploit idea: treat the targeted function as if an attacker can call it out of context and check whether private-call or promise-result assumptions fully hold.
- Invariant to test: NEP-141 to ERC-20 deployment must create exactly one canonical mirror with correct metadata and registration state
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Call the callback entry directly from tests with crafted input and compare behavior to the legitimate promise path. write integration tests for both legacy and metadata-based deployment paths, including direct callback invocation attempts and duplicate registration attempts
