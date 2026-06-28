# Q3934: silo and mirror enforcement router migration gap through private-or-owner split in `set_erc20_metadata`

## Question
Can an attacker exploit an update or migration boundary around private-or-owner split in `set_erc20_metadata` so old router assumptions and new router assumptions coexist long enough to misroute value and cause Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/silo/mod.rs + engine/src/contract_methods/connector.rs::mirror_erc20_token_callback + set_erc20_metadata / set_eth_connector_contract_account` -> `private-or-owner split in `set_erc20_metadata``
- Entrypoint: public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods
- Attacker controls: EVM sender address, predecessor account, incoming token address, direct callback calls, mirror arguments, and repeated timing around whitelist changes
- Exploit idea: attack router version transition semantics at the targeted step.
- Invariant to test: silo restrictions and mirror configuration must not be bypassable by public users or forged callback contexts
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Exercise the flow during a version change and compare behavior before, during, and after the update to ensure no mixed-version state is accepted. write tests that exercise deploy, submit, token-receive, and direct-callback paths with silo enabled, then assert whitelist, fallback, metadata, and connector configuration remain enforced
