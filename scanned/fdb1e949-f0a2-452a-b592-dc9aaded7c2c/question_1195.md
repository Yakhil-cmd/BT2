# Q1195: offers via assetIds 1195

## Question
Can an unprivileged attacker entering through the offer accept/cancel confirmation flow in `assetIds` (packages/gui/src/components/offers2/OfferBuilderTokensSection.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries after a failed RPC response and drive the sequence download or render content -> trigger linked wallet action so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderTokensSection.tsx` / `assetIds`
- Entrypoint: offer accept/cancel confirmation flow
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; after a failed RPC response
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
