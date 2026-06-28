# Q3952: silo and mirror enforcement retry recovery gap at private-or-owner split in `set_eth_connector_contract_account`

## Question
Can an attacker push private-or-owner split in `set_eth_connector_contract_account` into a failure state that cannot be retried safely but also does not restore consumed funds or metadata, leaving recoverability broken and causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/silo/mod.rs + engine/src/contract_methods/connector.rs::mirror_erc20_token_callback + set_erc20_metadata / set_eth_connector_contract_account` -> `private-or-owner split in `set_eth_connector_contract_account``
- Entrypoint: public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods
- Attacker controls: EVM sender address, predecessor account, incoming token address, direct callback calls, mirror arguments, and repeated timing around whitelist changes
- Exploit idea: force the targeted step into a non-idempotent failed state.
- Invariant to test: silo restrictions and mirror configuration must not be bypassable by public users or forged callback contexts
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Cause failure before and after the targeted mutation and verify every failed state has one safe retry or full refund path. write tests that exercise deploy, submit, token-receive, and direct-callback paths with silo enabled, then assert whitelist, fallback, metadata, and connector configuration remain enforced
