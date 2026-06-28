# Q2063: deploy_erc20_token() partial burn or refund at address return encoding after deployment

## Question
Can an attacker force address return encoding after deployment into a path where value is burned, escrowed, or promised before the success condition is finalized, then reclaim or replay value so the protocol loses funds and suffers Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/connector.rs::deploy_erc20_token / deploy_erc20_token_callback -> engine/src/engine.rs::deploy_erc20_token` -> `address return encoding after deployment`
- Entrypoint: `deploy_erc20_token()` and its callback on the Aurora engine contract
- Attacker controls: borsh `DeployErc20TokenArgs`, target NEP-141 account, metadata promise timing, callback invocation attempts, and repeated registration timing
- Exploit idea: attack ordering between burn/escrow and final success acknowledgement at the named step.
- Invariant to test: NEP-141 to ERC-20 deployment must create exactly one canonical mirror with correct metadata and registration state
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Instrument the failing downstream branch and assert burned or escrowed value is either fully restored or never consumed. write integration tests for both legacy and metadata-based deployment paths, including direct callback invocation attempts and duplicate registration attempts
