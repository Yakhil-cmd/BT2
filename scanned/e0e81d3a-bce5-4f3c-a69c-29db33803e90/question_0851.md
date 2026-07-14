# Q851: rpc-state via useOpenDialog 851

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `useOpenDialog` (packages/core/src/hooks/useOpenDialog.ts) control out-of-order event and query responses with a delayed metadata fetch and drive the sequence load persisted state -> render approval -> execute command so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useOpenDialog.ts` / `useOpenDialog`
- Entrypoint: daemon RPC response handling
- Attacker controls: out-of-order event and query responses; with a delayed metadata fetch
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
