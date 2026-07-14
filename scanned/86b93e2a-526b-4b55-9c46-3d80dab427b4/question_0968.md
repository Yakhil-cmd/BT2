# Q968: offers via NFTOfferPreview 968

## Question
Can an unprivileged attacker entering through the offer URL fetch/import flow in `NFTOfferPreview` (packages/gui/src/components/offers/NFTOfferPreview.tsx) control royalty and fee fields near zero/rounding limits after a failed RPC response and drive the sequence download or render content -> trigger linked wallet action so the GUI would cancel or accept a tradeId different from the row the user selected, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers/NFTOfferPreview.tsx` / `NFTOfferPreview`
- Entrypoint: offer URL fetch/import flow
- Attacker controls: royalty and fee fields near zero/rounding limits; after a failed RPC response
- Exploit idea: cancel or accept a tradeId different from the row the user selected
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
