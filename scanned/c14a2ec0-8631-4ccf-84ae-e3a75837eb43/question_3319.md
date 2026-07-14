# Q3319: offers via extractCrCatData 3319

## Question
Can an unprivileged attacker entering through the offer URL fetch/import flow in `extractCrCatData` (packages/gui/src/util/offerToOfferBuilderData.ts) control royalty and fee fields near zero/rounding limits after a failed RPC response and drive the sequence import -> parse -> preview -> submit so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/util/offerToOfferBuilderData.ts` / `extractCrCatData`
- Entrypoint: offer URL fetch/import flow
- Attacker controls: royalty and fee fields near zero/rounding limits; after a failed RPC response
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: simulate event ordering with fake timers and assert stale cache cannot drive a wallet-impacting action
