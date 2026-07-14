# Q970: offers via chiaWalletSelection 970

## Question
Can an unprivileged attacker entering through the offer accept/cancel confirmation flow in `chiaWalletSelection` (packages/gui/src/components/offers/NFTOfferTokenSelector.tsx) control royalty and fee fields near zero/rounding limits with reordered RPC events and drive the sequence fetch -> cache -> refresh -> submit so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/NFTOfferTokenSelector.tsx` / `chiaWalletSelection`
- Entrypoint: offer accept/cancel confirmation flow
- Attacker controls: royalty and fee fields near zero/rounding limits; with reordered RPC events
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
