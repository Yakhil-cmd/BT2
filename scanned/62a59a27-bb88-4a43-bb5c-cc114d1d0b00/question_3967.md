# Q3967: silo and mirror enforcement replayable funding around fixed-gas policy exposed by `get_fixed_gas` / `set_fixed_gas`

## Question
Can an attacker replay a funding or withdraw-intent through public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods so fixed-gas policy exposed by `get_fixed_gas` / `set_fixed_gas` processes the same logical XCC action more than once, causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/silo/mod.rs + engine/src/contract_methods/connector.rs::mirror_erc20_token_callback + set_erc20_metadata / set_eth_connector_contract_account` -> `fixed-gas policy exposed by `get_fixed_gas` / `set_fixed_gas``
- Entrypoint: public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods
- Attacker controls: EVM sender address, predecessor account, incoming token address, direct callback calls, mirror arguments, and repeated timing around whitelist changes
- Exploit idea: look for missing idempotence around router funding or async withdraw settlement.
- Invariant to test: silo restrictions and mirror configuration must not be bypassable by public users or forged callback contexts
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Replay the same funding intent under identical and reordered conditions and compare router balance, version state, and user balances. write tests that exercise deploy, submit, token-receive, and direct-callback paths with silo enabled, then assert whitelist, fallback, metadata, and connector configuration remain enforced
