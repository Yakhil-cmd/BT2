# Q3980: silo and mirror enforcement refund-less failure around fixed-gas policy exposed by `get_fixed_gas` / `set_fixed_gas`

## Question
Can an attacker make fixed-gas policy exposed by `get_fixed_gas` / `set_fixed_gas` fail after user value has been consumed but before any refund path becomes reachable, producing Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/silo/mod.rs + engine/src/contract_methods/connector.rs::mirror_erc20_token_callback + set_erc20_metadata / set_eth_connector_contract_account` -> `fixed-gas policy exposed by `get_fixed_gas` / `set_fixed_gas``
- Entrypoint: public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods
- Attacker controls: EVM sender address, predecessor account, incoming token address, direct callback calls, mirror arguments, and repeated timing around whitelist changes
- Exploit idea: seek a failure mode where the targeted XCC step consumes value without arming compensation logic.
- Invariant to test: silo restrictions and mirror configuration must not be bypassable by public users or forged callback contexts
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Cause failures at every downstream branch after the targeted step and assert user value is always restored or safely progressed. write tests that exercise deploy, submit, token-receive, and direct-callback paths with silo enabled, then assert whitelist, fallback, metadata, and connector configuration remain enforced
