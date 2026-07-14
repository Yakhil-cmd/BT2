# Q3656: rpc-state via setAutoHide 3656

## Question
Can an unprivileged attacker entering through the camel/snake case transform path in `setAutoHide` (packages/core/src/hooks/useScrollbarsSettings.tsx) control large numeric fields near JS precision limits after a failed RPC response and drive the sequence connect -> approve -> switch context -> execute so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/core/src/hooks/useScrollbarsSettings.tsx` / `setAutoHide`
- Entrypoint: camel/snake case transform path
- Attacker controls: large numeric fields near JS precision limits; after a failed RPC response
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: mock the service layer and assert no RPC call is made unless displayed and submitted fields match
