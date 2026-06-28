# Q3978: silo and mirror enforcement unfunded success signal from fixed-gas policy exposed by `get_fixed_gas` / `set_fixed_gas`

## Question
Can an attacker make fixed-gas policy exposed by `get_fixed_gas` / `set_fixed_gas` signal success for an XCC flow that is not actually funded enough to complete, so later value movement or callbacks fail and cause Insolvency?

## Target
- File/function: `engine/src/contract_methods/silo/mod.rs + engine/src/contract_methods/connector.rs::mirror_erc20_token_callback + set_erc20_metadata / set_eth_connector_contract_account` -> `fixed-gas policy exposed by `get_fixed_gas` / `set_fixed_gas``
- Entrypoint: public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods
- Attacker controls: EVM sender address, predecessor account, incoming token address, direct callback calls, mirror arguments, and repeated timing around whitelist changes
- Exploit idea: look for success reporting that outruns the actual funded state after the targeted step.
- Invariant to test: silo restrictions and mirror configuration must not be bypassable by public users or forged callback contexts
- Expected Immunefi impact: Insolvency
- Fast validation: Compare reported success with downstream NEAR-side balance and callback completion under minimum-funding cases. write tests that exercise deploy, submit, token-receive, and direct-callback paths with silo enabled, then assert whitelist, fallback, metadata, and connector configuration remain enforced
