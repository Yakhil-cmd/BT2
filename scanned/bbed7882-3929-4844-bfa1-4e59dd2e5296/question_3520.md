# Q3520: rpc-state via useGetLatestPeakTimestampQuery 3520

## Question
Can an unprivileged attacker entering through the WebSocket event subscription in `useGetLatestPeakTimestampQuery` (packages/api-react/src/hooks/useGetLatestPeakTimestampQuery.ts) control subscription event for a different wallet/fingerprint after a failed RPC response and drive the sequence preview -> mutate controlled state -> confirm so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that case conversion must not collapse distinct fields into privileged values, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api-react/src/hooks/useGetLatestPeakTimestampQuery.ts` / `useGetLatestPeakTimestampQuery`
- Entrypoint: WebSocket event subscription
- Attacker controls: subscription event for a different wallet/fingerprint; after a failed RPC response
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: case conversion must not collapse distinct fields into privileged values
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: exercise the Electron IPC or WalletConnect command handler with crafted params and assert approval classification is strict
