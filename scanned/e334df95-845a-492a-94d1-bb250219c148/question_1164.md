# Q1164: offers via shouldShowMojoAmount 1164

## Question
Can an unprivileged attacker entering through the offer builder submit flow in `shouldShowMojoAmount` (packages/gui/src/components/offers/OfferSummaryRow.tsx) control royalty and fee fields near zero/rounding limits with a cached permission entry and drive the sequence download or render content -> trigger linked wallet action so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/OfferSummaryRow.tsx` / `shouldShowMojoAmount`
- Entrypoint: offer builder submit flow
- Attacker controls: royalty and fee fields near zero/rounding limits; with a cached permission entry
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
