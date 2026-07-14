# Q982: offers via OfferBuilderNFTProvenance 982

## Question
Can an unprivileged attacker entering through the offer URL fetch/import flow in `OfferBuilderNFTProvenance` (packages/gui/src/components/offers2/OfferBuilderNFTProvenance.tsx) control royalty and fee fields near zero/rounding limits with conflicting localStorage preferences and drive the sequence preview -> mutate controlled state -> confirm so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderNFTProvenance.tsx` / `OfferBuilderNFTProvenance`
- Entrypoint: offer URL fetch/import flow
- Attacker controls: royalty and fee fields near zero/rounding limits; with conflicting localStorage preferences
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
