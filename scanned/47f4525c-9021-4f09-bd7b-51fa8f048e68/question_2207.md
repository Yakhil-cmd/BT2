# Q2207: rpc-state via WalletEmptyDialog 2207

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `WalletEmptyDialog` (packages/wallets/src/components/WalletEmptyDialog.tsx) control RPC error payload shaped like success after a failed RPC response and drive the sequence validate input -> normalize payload -> call RPC so the GUI would mis-handle precision for mojos, royalties, or fees in state, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/wallets/src/components/WalletEmptyDialog.tsx` / `WalletEmptyDialog`
- Entrypoint: camel/snake case transform path
- Attacker controls: RPC error payload shaped like success; after a failed RPC response
- Exploit idea: mis-handle precision for mojos, royalties, or fees in state
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
