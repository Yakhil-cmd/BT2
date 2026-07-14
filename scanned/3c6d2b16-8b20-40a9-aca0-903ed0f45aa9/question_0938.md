# Q938: rpc-state via createNewDIDWallet 938

## Question
Can an unprivileged attacker entering through the service command response correlation in `createNewDIDWallet` (packages/api/src/wallets/DID.ts) control response object with duplicate camelCase/snake_case keys with reordered RPC events and drive the sequence preview -> mutate controlled state -> confirm so the GUI would display one balance/asset state while executing with another, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/wallets/DID.ts` / `createNewDIDWallet`
- Entrypoint: service command response correlation
- Attacker controls: response object with duplicate camelCase/snake_case keys; with reordered RPC events
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
