# Q2440: relayer registration and function-call keys resource exhaustion seeded by address parsing in `read_input_arr20`

## Question
Can an attacker use `register_relayer()` plus any public path that can reach relayer-enabled `call`, `submit`, or `submit_with_args` behavior so that address parsing in `read_input_arr20` keeps creating state, promises, or registrations that the protocol must later pay to maintain, eventually causing Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield?

## Target
- File/function: `engine/src/contract_methods/admin.rs::register_relayer / add_relayer_key / store_relayer_key_callback / remove_relayer_key` -> `address parsing in `read_input_arr20``
- Entrypoint: `register_relayer()` plus any public path that can reach relayer-enabled `call`, `submit`, or `submit_with_args` behavior
- Attacker controls: user-selected relayer address bytes, repeated registrations, transaction ordering around relayer rewards, and any direct callback invocation attempts
- Exploit idea: look for unbounded public resource creation rooted in the targeted connector step.
- Invariant to test: relayer state must bind one account to one intended relayer address and must not let public users misroute gas rewards or stale function-call-key state
- Expected Immunefi impact: Direct theft of any user funds, whether at-rest or in-motion, other than unclaimed yield
- Fast validation: Run a high-count local sequence and measure whether protocol-held storage, registration state, or required connector balance grows without safe user-paid bounds. write integration tests that register and overwrite relayer mappings, then submit transactions through relayer paths and check reward routing and nonce behavior
