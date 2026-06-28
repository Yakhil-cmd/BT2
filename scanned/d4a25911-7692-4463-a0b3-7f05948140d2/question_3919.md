# Q3919: silo and mirror enforcement shared state overwrite via private-call enforcement in `mirror_erc20_token_callback`

## Question
Can an attacker use public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods to make private-call enforcement in `mirror_erc20_token_callback` overwrite shared XCC state that another in-flight operation still depends on, resulting in stranded or stolen value and Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/silo/mod.rs + engine/src/contract_methods/connector.rs::mirror_erc20_token_callback + set_erc20_metadata / set_eth_connector_contract_account` -> `private-call enforcement in `mirror_erc20_token_callback``
- Entrypoint: public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods
- Attacker controls: EVM sender address, predecessor account, incoming token address, direct callback calls, mirror arguments, and repeated timing around whitelist changes
- Exploit idea: look for non-namespaced XCC state touched by multiple public flows.
- Invariant to test: silo restrictions and mirror configuration must not be bypassable by public users or forged callback contexts
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Run overlapping operations against shared state and assert their metadata and balances do not overwrite each other. write tests that exercise deploy, submit, token-receive, and direct-callback paths with silo enabled, then assert whitelist, fallback, metadata, and connector configuration remain enforced
