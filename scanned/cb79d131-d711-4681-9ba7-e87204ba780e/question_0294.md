# Q294: rpc-state via isMainnet 294

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `isMainnet` (packages/gui/src/electron/api/isMainnet.ts) control out-of-order event and query responses with reordered RPC events and drive the sequence import -> parse -> preview -> submit so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/electron/api/isMainnet.ts` / `isMainnet`
- Entrypoint: daemon RPC response handling
- Attacker controls: out-of-order event and query responses; with reordered RPC events
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
