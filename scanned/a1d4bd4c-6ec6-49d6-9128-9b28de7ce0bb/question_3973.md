# Q3973: silo and mirror enforcement async order dependence in fixed-gas policy exposed by `get_fixed_gas` / `set_fixed_gas`

## Question
Can an attacker exploit asynchronous ordering around fixed-gas policy exposed by `get_fixed_gas` / `set_fixed_gas` so that two legitimate XCC flows complete in the wrong order and one overwrites or steals the other’s value or metadata, causing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/silo/mod.rs + engine/src/contract_methods/connector.rs::mirror_erc20_token_callback + set_erc20_metadata / set_eth_connector_contract_account` -> `fixed-gas policy exposed by `get_fixed_gas` / `set_fixed_gas``
- Entrypoint: public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods
- Attacker controls: EVM sender address, predecessor account, incoming token address, direct callback calls, mirror arguments, and repeated timing around whitelist changes
- Exploit idea: target ordering assumptions between multiple in-flight XCC operations touching the same state.
- Invariant to test: silo restrictions and mirror configuration must not be bypassable by public users or forged callback contexts
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Launch concurrent flows against the same address or sub-account and vary callback order while asserting final value and version state stay serializable. write tests that exercise deploy, submit, token-receive, and direct-callback paths with silo enabled, then assert whitelist, fallback, metadata, and connector configuration remain enforced
