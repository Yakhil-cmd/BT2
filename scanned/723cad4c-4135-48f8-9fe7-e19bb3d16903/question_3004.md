# Q3004: offers via OfferAsset 3004

## Question
Can an unprivileged attacker entering through the offer URL fetch/import flow in `OfferAsset` (packages/gui/src/components/offers/OfferAsset.ts) control NFT/CAT identifiers with duplicate or ambiguous entries after a profile switch and drive the sequence import -> parse -> preview -> submit so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that offer source changes must invalidate cached summaries before acceptance, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferAsset.ts` / `OfferAsset`
- Entrypoint: offer URL fetch/import flow
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; after a profile switch
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: offer source changes must invalidate cached summaries before acceptance
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
