# Q2028: deploy_erc20_token() gas starvation around bytecode construction in `setup_deploy_erc20_input`

## Question
Can an attacker choose input size or call ordering through `deploy_erc20_token()` and its callback on the Aurora engine contract so that bytecode construction in `setup_deploy_erc20_input` creates a promise graph with too little gas to finish safely, stranding funds or state and causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/connector.rs::deploy_erc20_token / deploy_erc20_token_callback -> engine/src/engine.rs::deploy_erc20_token` -> `bytecode construction in `setup_deploy_erc20_input``
- Entrypoint: `deploy_erc20_token()` and its callback on the Aurora engine contract
- Attacker controls: borsh `DeployErc20TokenArgs`, target NEP-141 account, metadata promise timing, callback invocation attempts, and repeated registration timing
- Exploit idea: target gas sizing logic attached to the connector promise or callback path.
- Invariant to test: NEP-141 to ERC-20 deployment must create exactly one canonical mirror with correct metadata and registration state
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Run low-prepaid-gas and high-input-size cases and assert the function cannot strand value or half-written mapping state when gas is tight. write integration tests for both legacy and metadata-based deployment paths, including direct callback invocation attempts and duplicate registration attempts
