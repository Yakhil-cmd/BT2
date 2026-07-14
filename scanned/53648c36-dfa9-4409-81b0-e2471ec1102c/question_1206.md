# Q1206: offers via infos 1206

## Question
Can an unprivileged attacker entering through the offer builder submit flow in `infos` (packages/gui/src/components/offers2/OfferDetails.tsx) control NFT/CAT identifiers with duplicate or ambiguous entries after a profile switch and drive the sequence subscribe event -> update cache -> open action dialog so the GUI would resolve a remote offer to stale data after the preview step, violating the invariant that previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC, leading to Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets?

## Target
- File/function: `packages/gui/src/components/offers2/OfferDetails.tsx` / `infos`
- Entrypoint: offer builder submit flow
- Attacker controls: NFT/CAT identifiers with duplicate or ambiguous entries; after a profile switch
- Exploit idea: resolve a remote offer to stale data after the preview step
- Invariant to test: previewed offered/requested assets, royalties, fees, tradeId, and expiration must equal the payload sent to wallet RPC
- Expected Immunefi impact: Critical: unauthorized offer acceptance/cancellation or wrong-asset transfer; High: spoofed offer state causing approval of the wrong assets
- Fast validation: fuzz canonicalization inputs and assert display, validation, and payload use the same canonical value
