# Q940: rpc-state via createNewDIDWallet 940

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `createNewDIDWallet` (packages/api/src/wallets/DID.ts) control out-of-order event and query responses with reordered RPC events and drive the sequence preview -> mutate controlled state -> confirm so the GUI would display one balance/asset state while executing with another, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/wallets/DID.ts` / `createNewDIDWallet`
- Entrypoint: daemon RPC response handling
- Attacker controls: out-of-order event and query responses; with reordered RPC events
- Exploit idea: display one balance/asset state while executing with another
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
