# Q2472: relayer registration and function-call keys mapping collision around private-call enforcement in the key-storage callback

## Question
Can an attacker choose inputs through `register_relayer()` plus any public path that can reach relayer-enabled `call`, `submit`, or `submit_with_args` behavior so that private-call enforcement in the key-storage callback collides two distinct users, assets, or registrations into one storage key or one effective route, causing Temporary freezing of funds?

## Target
- File/function: `engine/src/contract_methods/admin.rs::register_relayer / add_relayer_key / store_relayer_key_callback / remove_relayer_key` -> `private-call enforcement in the key-storage callback`
- Entrypoint: `register_relayer()` plus any public path that can reach relayer-enabled `call`, `submit`, or `submit_with_args` behavior
- Attacker controls: user-selected relayer address bytes, repeated registrations, transaction ordering around relayer rewards, and any direct callback invocation attempts
- Exploit idea: target the storage key or mapping derivation consumed by the named step.
- Invariant to test: relayer state must bind one account to one intended relayer address and must not let public users misroute gas rewards or stale function-call-key state
- Expected Immunefi impact: Temporary freezing of funds
- Fast validation: Search for colliding identifiers under fuzzed account and asset inputs and assert the contract always preserves one-to-one mappings. write integration tests that register and overwrite relayer mappings, then submit transactions through relayer paths and check reward routing and nonce behavior
