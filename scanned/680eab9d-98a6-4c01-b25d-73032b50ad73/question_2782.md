# Q2782: rpc-state via hasSensitiveContent 2782

## Question
Can an unprivileged attacker entering through the daemon RPC response handling in `hasSensitiveContent` (packages/gui/src/util/hasSensitiveContent.ts) control out-of-order event and query responses with hidden Unicode characters and drive the sequence connect -> approve -> switch context -> execute so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/gui/src/util/hasSensitiveContent.ts` / `hasSensitiveContent`
- Entrypoint: daemon RPC response handling
- Attacker controls: out-of-order event and query responses; with hidden Unicode characters
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
