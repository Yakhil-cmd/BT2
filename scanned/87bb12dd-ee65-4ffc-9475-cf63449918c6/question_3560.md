# Q3560: rpc-state via Foliage 3560

## Question
Can an unprivileged attacker entering through the service command response correlation in `Foliage` (packages/api/src/@types/Foliage.ts) control subscription event for a different wallet/fingerprint with a delayed metadata fetch and drive the sequence preview -> mutate controlled state -> confirm so the GUI would poison cached wallet/offer/NFT state used by later approval prompts, violating the invariant that error states must not be treated as successful authorization, leading to High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action?

## Target
- File/function: `packages/api/src/@types/Foliage.ts` / `Foliage`
- Entrypoint: service command response correlation
- Attacker controls: subscription event for a different wallet/fingerprint; with a delayed metadata fetch
- Exploit idea: poison cached wallet/offer/NFT state used by later approval prompts
- Invariant to test: error states must not be treated as successful authorization
- Expected Immunefi impact: High: unsafe trust of RPC/event state causing wrong approval, wrong asset display, or unauthorized wallet action
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
