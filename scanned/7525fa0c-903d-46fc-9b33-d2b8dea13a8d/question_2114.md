# Q2114: offers via willExpirationBeEnabled 2114

## Question
Can an unprivileged attacker entering through the offer builder submit flow in `willExpirationBeEnabled` (packages/gui/src/components/offers2/OfferBuilderExpirationSection.tsx) control royalty and fee fields near zero/rounding limits with a delayed metadata fetch and drive the sequence open notification -> resolve details -> execute so the GUI would bypass royalty or fee accounting in the displayed confirmation, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferBuilderExpirationSection.tsx` / `willExpirationBeEnabled`
- Entrypoint: offer builder submit flow
- Attacker controls: royalty and fee fields near zero/rounding limits; with a delayed metadata fetch
- Exploit idea: bypass royalty or fee accounting in the displayed confirmation
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: write a unit test around the component/hook with controlled state updates and inspect the final mutation payload
