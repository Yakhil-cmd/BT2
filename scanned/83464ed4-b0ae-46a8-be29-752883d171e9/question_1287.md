# Q1287: rpc-state via if 1287

## Question
Can an unprivileged attacker entering through the RTK query cache update in `if` (packages/wallets/src/components/WalletName.tsx) control response object with duplicate camelCase/snake_case keys after a network switch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would display one balance/asset state while executing with another, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletName.tsx` / `if`
- Entrypoint: RTK query cache update
- Attacker controls: response object with duplicate camelCase/snake_case keys; after a network switch
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
