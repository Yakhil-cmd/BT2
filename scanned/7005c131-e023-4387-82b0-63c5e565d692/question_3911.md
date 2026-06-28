# Q3911: silo and mirror enforcement owner/public split around private-call enforcement in `mirror_erc20_token_callback`

## Question
Can an attacker exploit a public branch in public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods that is safe only when the owner chooses certain defaults, so private-call enforcement in `mirror_erc20_token_callback` still reaches privileged-looking XCC behavior and causes Permanent freezing of funds?

## Target
- File/function: `engine/src/contract_methods/silo/mod.rs + engine/src/contract_methods/connector.rs::mirror_erc20_token_callback + set_erc20_metadata / set_eth_connector_contract_account` -> `private-call enforcement in `mirror_erc20_token_callback``
- Entrypoint: public user flows through `submit()`, `deploy_code()`, `ft_on_transfer()`, or direct invocation attempts against callback-style or private-or-owner methods
- Attacker controls: EVM sender address, predecessor account, incoming token address, direct callback calls, mirror arguments, and repeated timing around whitelist changes
- Exploit idea: use the public branch to reach the same destination the owner-only branch was expected to guard.
- Invariant to test: silo restrictions and mirror configuration must not be bypassable by public users or forged callback contexts
- Expected Immunefi impact: Permanent freezing of funds
- Fast validation: Compare owner and public variants of the same flow and assert public callers cannot mutate the same protected router or funding state. write tests that exercise deploy, submit, token-receive, and direct-callback paths with silo enabled, then assert whitelist, fallback, metadata, and connector configuration remain enforced
